using System;
using System.Text.Json;
using System.Text.Json.Serialization;
using Impostor.Api.Innersloth;
using Impostor.Server.Net.Cache;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace Impostor.Server.Http;

/// <summary>
/// Issues matchmaker tokens for the /api/user endpoint.
///
/// Flow:
///   1. Client POSTs {Puid, Username, ClientVersion, Language, FriendCode}
///   2. Server generates a unique nonce, stores nonce→(puid, friendCode) in PuidFriendCodeCache
///   3. Server embeds the nonce in the token payload (field "Nonce")
///   4. Client receives the base64 token, extracts LastNonceReceived = token.Content.Nonce
///      Wait — the official client reads LastNonceReceived from the DTLS auth server, not from
///      the token content.  But the token IS passed as-is to GetConnectionData as
///      matchmakerToken (for useDtls=false path the nonce uint32 is written directly).
///
///   For the useDtls=false path (custom servers):
///   - Client writes LastNonceReceived.GetValueOrDefault() as a uint32 in the UDP hello.
///   - LastNonceReceived is set by AuthManager.Connection_DataReceived after the DTLS auth.
///   - On failure (no DTLS auth), LastNonceReceived stays null → uint32 = 0.
///
///   We can't inject a nonce via the token on this path directly.
///   HOWEVER the FriendCode IS accessible: the client sends it in the DTLS BuildData payload.
///   Since we receive those DTLS UDP packets on port+2 (AuthNonceServer), we can read
///   version+platform+token+FriendCode from the DTLS ClientHello application_data extension,
///   then send back a proper nonce.
///
///   Revised approach implemented here:
///   - Embed the nonce as a custom "Nonce" field in the token JSON.
///   - AuthNonceServer reads the DTLS ClientHello, extracts the token (which is the
///     matchmakerToken string in BuildData), parses it to get the nonce, then replies
///     with that nonce in a fake "nonce message" so the client's CoWaitForNonce succeeds
///     and LastNonceReceived equals the nonce we stored in PuidFriendCodeCache.
///   - UDP handshake then carries this nonce, and ClientManager can look up puid/friendCode.
/// </summary>
[Route("/api/user")]
[ApiController]
public sealed class TokenController : ControllerBase
{
    private readonly PuidFriendCodeCache _puidCache;
    private readonly ILogger<TokenController> _logger;

    public TokenController(PuidFriendCodeCache puidCache, ILogger<TokenController> logger)
    {
        _puidCache = puidCache;
        _logger = logger;
    }

    [HttpPost]
    public IActionResult GetToken([FromBody] TokenRequest request)
    {
        var friendCode = request.FriendCode ?? string.Empty;
        var puid = request.ProductUserId ?? string.Empty;

        // Generate nonce and register mapping; FriendCode is stored in cache
        var nonce = _puidCache.RegisterAndGetNonce(puid, friendCode);

        _logger.LogInformation(
            "HTTP /api/user: Puid={Puid} FriendCode={FriendCode} → Nonce={Nonce:X8}",
            puid,
            string.IsNullOrEmpty(friendCode) ? "(none)" : friendCode,
            nonce);

        var token = new Token
        {
            Content = new TokenPayload
            {
                ProductUserId = puid,
                ClientVersion = request.ClientVersion,
                // Nonce embedded here so AuthNonceServer can extract it from the DTLS payload
                Nonce = nonce,
            },
            Hash = "impostor_was_here",
        };

        var serialized = JsonSerializer.SerializeToUtf8Bytes(token);
        return this.Ok(Convert.ToBase64String(serialized));
    }

    public class TokenRequest
    {
        [JsonPropertyName("Puid")]
        public required string ProductUserId { get; init; }

        [JsonPropertyName("Username")]
        public required string Username { get; init; }

        [JsonPropertyName("ClientVersion")]
        public required int ClientVersion { get; init; }

        [JsonPropertyName("Language")]
        public required Language Language { get; init; }

        [JsonPropertyName("FriendCode")]
        public string? FriendCode { get; init; }
    }

    public sealed class Token
    {
        [JsonPropertyName("Content")]
        public required TokenPayload Content { get; init; }

        [JsonPropertyName("Hash")]
        public required string Hash { get; init; }
    }

    public sealed class TokenPayload
    {
        private static readonly DateTime DefaultExpiryDate = new(2099, 12, 31);

        [JsonPropertyName("Puid")]
        public required string ProductUserId { get; init; }

        [JsonPropertyName("ClientVersion")]
        public required int ClientVersion { get; init; }

        [JsonPropertyName("ExpiresAt")]
        public DateTime ExpiresAt { get; init; } = DefaultExpiryDate;

        /// <summary>
        /// Custom field: the nonce this client should echo back in its UDP hello.
        /// AuthNonceServer reads this from the DTLS hello payload to send back to the client.
        /// </summary>
        [JsonPropertyName("Nonce")]
        public uint Nonce { get; init; }
    }
}
