using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Impostor.Server.Net.Cache
{
    /// <summary>
    /// Two-layer store:
    ///
    /// 1. Transient  nonce (uint32) → (Puid, FriendCode)
    ///    Filled when the client calls /api/user (HTTP). The server generates a unique
    ///    random nonce, embeds it in the token, and records it here.
    ///    When the client later connects via UDP it echoes back the same nonce
    ///    (HandshakeC2S.ReadUInt32 == lastNonceReceived).  The UDP handler looks up
    ///    the nonce here to obtain Puid/FriendCode without any IP matching.
    ///    Entries are removed after consumption (one-shot).
    ///
    /// 2. Persistent  Puid → FriendCode  (Data/puid_friendcode_cache.json)
    ///    Every time a (puid, friendCode) pair is seen with a non-empty FriendCode
    ///    it is written here.  On next login the FriendCode can be served even if
    ///    the client omits it in the token request.
    /// </summary>
    public class PuidFriendCodeCache
    {
        private static readonly string DataDirectory =
            Path.Combine(AppContext.BaseDirectory, "Data");

        private static readonly string CacheFilePath =
            Path.Combine(DataDirectory, "puid_friendcode_cache.json");

        private readonly ILogger<PuidFriendCodeCache> _logger;
        private readonly Random _random = new();

        // nonce → (puid, friendCode)  – transient
        private readonly ConcurrentDictionary<uint, (string Puid, string FriendCode, DateTime CreatedAt)>
            _nonceToInfo = new();

        // puid → friendCode  – persisted
        private readonly ConcurrentDictionary<string, string> _puidToFriendCode = new();

        public PuidFriendCodeCache(ILogger<PuidFriendCodeCache> logger)
        {
            _logger = logger;
            LoadFromDisk();
        }

        // ── HTTP phase ──────────────────────────────────────────────────────────

        /// <summary>
        /// Called by TokenController when a /api/user request arrives.
        /// Generates a unique nonce, stores the mapping, and returns the nonce
        /// to be embedded in the matchmaker token.
        /// </summary>
        public uint RegisterAndGetNonce(string puid, string friendCode)
        {
            // Purge stale entries (older than 60 s) to avoid memory growth
            var cutoff = DateTime.UtcNow.AddSeconds(-60);
            foreach (var kvp in _nonceToInfo)
            {
                if (kvp.Value.CreatedAt < cutoff)
                    _nonceToInfo.TryRemove(kvp.Key, out _);
            }

            // Persist friendCode if available
            if (!string.IsNullOrEmpty(puid) && !string.IsNullOrEmpty(friendCode))
                UpdateCache(puid, friendCode);

            // If we don't have a friendCode yet, try the persistent cache
            if (string.IsNullOrEmpty(friendCode) && !string.IsNullOrEmpty(puid))
                _puidToFriendCode.TryGetValue(puid, out friendCode!);

            friendCode ??= string.Empty;

            // Generate a unique nonce (avoid collisions)
            uint nonce;
            do
            {
                nonce = (uint)(_random.Next(1, int.MaxValue));
            }
            while (_nonceToInfo.ContainsKey(nonce));

            _nonceToInfo[nonce] = (puid, friendCode, DateTime.UtcNow);

            _logger.LogDebug(
                "Issued nonce {Nonce:X8} for Puid={Puid}, FriendCode={FriendCode}",
                nonce, puid, string.IsNullOrEmpty(friendCode) ? "(none)" : friendCode);

            return nonce;
        }

        // ── UDP phase ───────────────────────────────────────────────────────────

        /// <summary>
        /// Called by ClientManager when a UDP connection sends its Hello packet.
        /// Looks up (puid, friendCode) by the nonce the client echoed back.
        /// Returns false if the nonce is unknown (e.g. direct connect without /api/user).
        /// </summary>
        public bool TryConsumeNonce(uint nonce, out string puid, out string friendCode)
        {
            if (nonce != 0 && _nonceToInfo.TryRemove(nonce, out var info))
            {
                puid = info.Puid;
                friendCode = info.FriendCode;
                return true;
            }

            puid = string.Empty;
            friendCode = string.Empty;
            return false;
        }

        // ── Persistent cache ────────────────────────────────────────────────────

        public bool TryGetFriendCode(string puid, out string friendCode) =>
            _puidToFriendCode.TryGetValue(puid, out friendCode!);

        public void UpdateCache(string puid, string friendCode)
        {
            if (string.IsNullOrEmpty(puid) || string.IsNullOrEmpty(friendCode))
                return;

            if (_puidToFriendCode.TryGetValue(puid, out var existing) && existing == friendCode)
                return; // no change

            _puidToFriendCode[puid] = friendCode;
            _ = Task.Run(SaveToDiskAsync);
        }

        private void LoadFromDisk()
        {
            try
            {
                if (!Directory.Exists(DataDirectory))
                    Directory.CreateDirectory(DataDirectory);

                if (!File.Exists(CacheFilePath))
                    return;

                var json = File.ReadAllText(CacheFilePath);
                var dict = JsonSerializer.Deserialize<Dictionary<string, string>>(json);
                if (dict == null) return;

                foreach (var kvp in dict)
                    _puidToFriendCode[kvp.Key] = kvp.Value;

                _logger.LogInformation(
                    "Loaded {Count} PUID→FriendCode entries from disk cache.", dict.Count);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load PUID→FriendCode cache from disk.");
            }
        }

        private async Task SaveToDiskAsync()
        {
            try
            {
                if (!Directory.Exists(DataDirectory))
                    Directory.CreateDirectory(DataDirectory);

                var snapshot = new Dictionary<string, string>(_puidToFriendCode);
                var json = JsonSerializer.Serialize(snapshot,
                    new JsonSerializerOptions { WriteIndented = true });
                await File.WriteAllTextAsync(CacheFilePath, json);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to save PUID→FriendCode cache to disk.");
            }
        }
    }
}
