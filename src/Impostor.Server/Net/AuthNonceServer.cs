using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Impostor.Api.Config;
using Impostor.Server.Net.Cache;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Impostor.Server.Net
{
    /// <summary>
    /// Lightweight UDP server on gamePort+2.
    ///
    /// The Among Us client (non-DTLS game path) sends a DTLS ClientHello to this port
    /// with an application_data extension that contains (via Hazel MessageWriter):
    ///   int32   broadcastVersion
    ///   byte    platform
    ///   string  matchmakerToken   (base64 JSON with embedded Nonce from TokenController)
    ///   string  friendCode
    ///
    /// We extract the token, parse the Nonce field, and reply with a fake Hazel "reliable"
    /// message containing that nonce.  The client's CoWaitForNonce then succeeds immediately
    /// (instead of timing out after 5 s), and LastNonceReceived equals the nonce we stored
    /// in PuidFriendCodeCache, allowing correct puid/friendCode lookup during UDP handshake.
    ///
    /// DTLS record format (RFC 6347):
    ///   ContentType (1) | Version (2) | Epoch (2) | SeqNum (6) | Length (2) | Fragment
    /// ContentType 22 = Handshake; the ClientHello extension data is what interests us.
    /// We do NOT implement a full DTLS stack — we only need to extract the hello data
    /// from the first ClientHello record that the client sends.
    ///
    /// The nonce reply uses the same fake-Hazel-reliable format that the client expects:
    ///   0x01 (Reliable) | 0x00 0x01 (seqId) | [len=5 BE] | [tag=1] | [nonce uint32 LE]
    /// </summary>
    internal class AuthNonceServer : IHostedService
    {
        private readonly ILogger<AuthNonceServer> _logger;
        private readonly ServerConfig _serverConfig;
        private readonly PuidFriendCodeCache _puidCache;
        private UdpClient? _socket;
        private CancellationTokenSource? _cts;

        public AuthNonceServer(
            ILogger<AuthNonceServer> logger,
            IOptions<ServerConfig> serverConfig,
            PuidFriendCodeCache puidCache)
        {
            _logger = logger;
            _serverConfig = serverConfig.Value;
            _puidCache = puidCache;
        }

        public Task StartAsync(CancellationToken cancellationToken)
        {
            var listenIp = _serverConfig.ResolveListenIp();
            var authPort = (ushort)(_serverConfig.ListenPort + 2);

            try
            {
                _socket = new UdpClient(AddressFamily.InterNetwork);
                _socket.Client.Bind(new IPEndPoint(IPAddress.Parse(listenIp), authPort));
                _cts = new CancellationTokenSource();
                _ = Task.Factory.StartNew(
                    () => ListenLoop(_cts.Token),
                    _cts.Token,
                    TaskCreationOptions.LongRunning,
                    TaskScheduler.Default);

                _logger.LogInformation(
                    "Auth nonce server listening on {Ip}:{Port}.",
                    listenIp, authPort);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex,
                    "Failed to start auth nonce server on port {Port}. " +
                    "Players will experience a ~5 s join delay.", authPort);
            }

            return Task.CompletedTask;
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _cts?.Cancel();
            await Task.Delay(500, CancellationToken.None);
            _socket?.Dispose();
        }

        // ── Receive loop ────────────────────────────────────────────────────────

        private async Task ListenLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var result = await _socket!.ReceiveAsync(ct);
                    _ = Task.Run(() => HandlePacket(result), ct);
                }
                catch (OperationCanceledException) { break; }
                catch (ObjectDisposedException) { break; }
                catch (Exception ex) { _logger.LogDebug(ex, "AuthNonceServer recv error."); }
            }
        }

        // ── Packet handling ─────────────────────────────────────────────────────

        private async Task HandlePacket(UdpReceiveResult result)
        {
            try
            {
                var data = result.Buffer;
                var remote = result.RemoteEndPoint;

                // Try to extract the nonce from the DTLS hello payload
                var nonce = TryExtractNonce(data);

                if (nonce == null)
                {
                    // Packet we can't parse — send a DTLS fatal alert so the client
                    // disconnects quickly instead of waiting 5 s for the timeout.
                    await SendDtlsAlertAsync(remote);
                    return;
                }

                // Send back a Hazel "reliable" nonce message so CoWaitForNonce succeeds
                await SendNonceReplyAsync(remote, nonce.Value);

                _logger.LogDebug(
                    "Sent nonce {Nonce:X8} to {Remote}.", nonce.Value, remote);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "AuthNonceServer handle error.");
            }
        }

        // ── Nonce extraction from DTLS ClientHello ──────────────────────────────

        /// <summary>
        /// Attempts to find the matchmaker token inside a DTLS ClientHello record,
        /// parse it as a JSON Token (base64), and return the Nonce field.
        ///
        /// DTLS Record: [type(1), ver(2), epoch(2), seq(6), length(2), fragment...]
        /// Handshake fragment: [msg_type(1), length(3), seq(2), frag_off(3), frag_len(3), body...]
        /// ClientHello body: [ver(2), random(32), session_id_len(1+), cookie_len(1+),
        ///                     cipher_suites_len(2)+..., compression_len(1)+..., extensions...]
        ///
        /// The extension we're interested in is the TLS "user data" carried in the
        /// Hazel BuildData byte array.  Hazel's DtlsUnityConnection embeds this as
        /// an extension (or in the cookie field for subsequent flights).
        ///
        /// In practice, Hazel sends the BuildData as extension type 0xFF01 in the ClientHello.
        /// We search for the base64-looking token string without fully parsing all extensions.
        /// </summary>
        private uint? TryExtractNonce(byte[] data)
        {
            // The DTLS record starts with type(1)+ver(2)+epoch(2)+seq(6)+len(2) = 13 bytes
            if (data.Length < 14) return null;

            // We search the raw bytes for the base64 token by looking for the Hazel string
            // encoding of the token (variable-length packed int prefix + UTF-8 bytes).
            // Rather than full DTLS parsing, we scan for the first '{' that could be the
            // start of base64-decoded JSON, but the token is base64 encoded as a string.
            // Instead: find Hazel packed-string sequences that decode to valid base64 JSON.

            // Hazel writes strings as: packed_int(length) + UTF-8 bytes
            // We scan for lengths that could be a base64 token (40–600 bytes)
            // and try to decode+parse them.
            var fullText = Encoding.UTF8.GetString(data);

            // Look for base64 substrings (A-Za-z0-9+/=, 40+ chars)
            return TryScanForToken(data);
        }

        private uint? TryScanForToken(byte[] data)
        {
            // Scan the raw byte array for Hazel-packed strings that look like base64 tokens
            // Hazel packed int: if value < 128, one byte; else high bit set, next byte follows
            for (int i = 0; i < data.Length - 4; i++)
            {
                int len;
                int start;

                // Try single-byte length prefix
                var b0 = data[i];
                if ((b0 & 0x80) == 0)
                {
                    len = b0;
                    start = i + 1;
                }
                else if (i + 1 < data.Length)
                {
                    // Two-byte packed int
                    var b1 = data[i + 1];
                    len = ((b0 & 0x7F) | (b1 << 7));
                    start = i + 2;
                }
                else continue;

                if (len < 20 || start + len > data.Length) continue;

                // Must look like base64 (all chars in [A-Za-z0-9+/=])
                if (!IsBase64Region(data, start, len)) continue;

                // Try to decode and parse as Token JSON
                try
                {
                    var base64 = Encoding.UTF8.GetString(data, start, len);
                    var json = Encoding.UTF8.GetString(Convert.FromBase64String(base64));
                    var token = JsonSerializer.Deserialize<ParsedToken>(json);
                    if (token?.Content?.Nonce > 0 && !string.IsNullOrEmpty(token.Content.Puid))
                    {
                        _logger.LogDebug(
                            "Extracted Puid={Puid} Nonce={Nonce:X8} from DTLS hello.",
                            token.Content.Puid, token.Content.Nonce);
                        return token.Content.Nonce;
                    }
                }
                catch { /* not a valid token, keep scanning */ }
            }

            return null;
        }

        private static bool IsBase64Region(byte[] data, int start, int len)
        {
            for (int j = start; j < start + len; j++)
            {
                var c = (char)data[j];
                if (!((c >= 'A' && c <= 'Z') ||
                      (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') ||
                       c == '+' || c == '/' || c == '='))
                    return false;
            }
            return true;
        }

        // ── Response builders ───────────────────────────────────────────────────

        /// <summary>
        /// Sends the nonce back as a Hazel Reliable message (what AuthManager expects).
        /// Layout: type=Reliable(1) | seqHi seqLo | subMsgLen(2 BE) | tag(1) | nonce(4 LE)
        /// </summary>
        private async Task SendNonceReplyAsync(IPEndPoint remote, uint nonce)
        {
            var reply = new byte[]
            {
                0x01,         // MessageType.Reliable
                0x00, 0x01,   // Sequence number = 1
                0x00, 0x05,   // Sub-message length = 5
                0x01,         // Tag = 1  (AuthTagNonceMessage)
                (byte)(nonce & 0xFF),
                (byte)((nonce >> 8) & 0xFF),
                (byte)((nonce >> 16) & 0xFF),
                (byte)((nonce >> 24) & 0xFF),
            };
            await _socket!.SendAsync(reply, reply.Length, remote);
        }

        /// <summary>
        /// Sends a DTLS fatal alert so the DtlsUnityConnection transitions out of
        /// Connecting state quickly, causing CoWaitForNonce to exit early.
        /// </summary>
        private async Task SendDtlsAlertAsync(IPEndPoint remote)
        {
            // DTLS 1.0 fatal close_notify
            var alert = new byte[]
            {
                0x15,                                       // ContentType = Alert
                0xFE, 0xFF,                                 // Version = DTLS 1.0
                0x00, 0x00,                                 // Epoch = 0
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00,        // SequenceNumber = 0
                0x00, 0x02,                                 // Length = 2
                0x02,                                       // Level = fatal
                0x00,                                       // Description = close_notify
            };
            await _socket!.SendAsync(alert, alert.Length, remote);
            _logger.LogDebug("Sent DTLS fatal alert to {Remote} (no token found).", remote);
        }

        // ── JSON models for token parsing ───────────────────────────────────────

        private sealed class ParsedToken
        {
            [System.Text.Json.Serialization.JsonPropertyName("Content")]
            public ParsedPayload? Content { get; set; }
        }

        private sealed class ParsedPayload
        {
            [System.Text.Json.Serialization.JsonPropertyName("Puid")]
            public string? Puid { get; set; }

            [System.Text.Json.Serialization.JsonPropertyName("Nonce")]
            public uint Nonce { get; set; }
        }
    }
}
