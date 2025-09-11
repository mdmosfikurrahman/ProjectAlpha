namespace ProjectAlpha.Application.Services;

public interface ITokenBlacklist
{
    void Revoke(string jti, DateTime? expiresUtc);
    bool IsBlacklisted(string jti);
}

public class InMemoryTokenBlacklist : ITokenBlacklist
{
    // jti -> expiry
    private readonly Dictionary<string, DateTime> _revoked = new();
    private readonly object _lock = new();

    public void Revoke(string jti, DateTime? expiresUtc)
    {
        lock (_lock)
        {
            _revoked[jti] = expiresUtc ?? DateTime.UtcNow.AddHours(1);
            // Cleanup expired items opportunistically
            var now = DateTime.UtcNow;
            var toRemove = _revoked.Where(kv => kv.Value < now).Select(kv => kv.Key).ToList();
            foreach (var key in toRemove) _revoked.Remove(key);
        }
    }

    public bool IsBlacklisted(string jti)
    {
        lock (_lock)
        {
            if (_revoked.TryGetValue(jti, out var exp))
            {
                if (exp > DateTime.UtcNow) return true;
                _revoked.Remove(jti);
            }
            return false;
        }
    }
}