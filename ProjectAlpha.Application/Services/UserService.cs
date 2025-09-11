namespace ProjectAlpha.Application.Services;

public interface IUserService
{
    (string userId, string userName, IEnumerable<string> roles)? ValidateCredentials(string username, string password);
}

public class InMemoryUserService : IUserService
{
    private readonly Dictionary<string, (string pwd, string id, string[] roles)> _users = new(StringComparer.OrdinalIgnoreCase)
    {
        ["admin"] = ("admin@123", Guid.NewGuid().ToString(), ["Admin"]),
        ["user"]  = ("user@123",  Guid.NewGuid().ToString(), ["User"])
    };

    public (string userId, string userName, IEnumerable<string> roles)? ValidateCredentials(string username, string password)
    {
        if (_users.TryGetValue(username, out var info) && info.pwd == password)
            return (info.id, username, info.roles);

        return null;
    }
}