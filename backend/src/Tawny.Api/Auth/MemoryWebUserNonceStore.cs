using System.Collections.Concurrent;

namespace Tawny.Api.Auth;

public sealed class MemoryWebUserNonceStore : IWebUserNonceStore
{
    private readonly ConcurrentDictionary<string, long> _nonces = new(StringComparer.Ordinal);
    private long _lastPurgeTicks;

    public bool TryAccept(string nonce, TimeSpan ttl)
    {
        if (string.IsNullOrWhiteSpace(nonce) || nonce.Length is < 16 or > 128)
        {
            return false;
        }

        MaybePurge();
        var expiresAt = DateTimeOffset.UtcNow.Add(ttl).UtcTicks;
        return _nonces.TryAdd(nonce, expiresAt);
    }

    private void MaybePurge()
    {
        var now = DateTimeOffset.UtcNow.UtcTicks;
        var last = Interlocked.Read(ref _lastPurgeTicks);
        // Purge at most once every 5 seconds.
        if (now - last < TimeSpan.FromSeconds(5).Ticks)
        {
            return;
        }

        if (Interlocked.CompareExchange(ref _lastPurgeTicks, now, last) != last)
        {
            return;
        }

        foreach (var (key, expiresAt) in _nonces)
        {
            if (expiresAt <= now)
            {
                _nonces.TryRemove(key, out _);
            }
        }
    }
}
