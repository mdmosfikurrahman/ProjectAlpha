using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using ProjectAlpha.Shared.Dto;
using static ProjectAlpha.Shared.Dto.ApiResponseHelper;

namespace ProjectAlpha.Application.Services;

public interface IAuthService
{
    Task<StandardResponse> LoginAsync(string username, string password);
    Task<StandardResponse> LogoutAsync(string authorizationHeader);
    Task<StandardResponse> MeAsync(ClaimsPrincipal user);
}

public class AuthService(IUserService users, ITokenService tokens, ITokenBlacklist blacklist) : IAuthService
{
    public Task<StandardResponse> LoginAsync(string username, string password)
    {
        var result = users.ValidateCredentials(username, password);
        if (result is null)
            return Task.FromResult(Unauthorized("Auth", "Invalid credentials."));

        var (userId, userName, roles) = result.Value;
        var accessToken = tokens.CreateAccessToken(userId, userName, roles);

        return Task.FromResult(Success("Auth Token", new
        {
            accessToken,
            tokenType = "Bearer"
        }));
    }

    public Task<StandardResponse> LogoutAsync(string authorizationHeader)
    {
        var token = ExtractBearer(authorizationHeader);
        if (string.IsNullOrWhiteSpace(token))
            return Task.FromResult(ValidationError("Auth", [ new ErrorDetails("Authorization", "Bearer token not found.") ]));

        JwtSecurityToken jwt;
        try
        {
            jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
        }
        catch
        {
            return Task.FromResult(ValidationError("Auth", [ new ErrorDetails("Authorization", "Invalid token format.") ]));
        }

        var jti = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Jti || c.Type == "jti")?.Value;
        var expUnix = jwt.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Exp)?.Value;

        if (string.IsNullOrEmpty(jti))
            return Task.FromResult(ValidationError("Auth", [ new ErrorDetails("jti", "Token id is missing.") ]));

        DateTime? expUtc = null;
        if (long.TryParse(expUnix, out var expSeconds))
            expUtc = DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime;

        blacklist.Revoke(jti, expUtc);

        return Task.FromResult(Success("Logout", new { revoked = true }));
    }

    public Task<StandardResponse> MeAsync(ClaimsPrincipal user)
    {
        var sub  = user.FindFirst(ClaimTypes.NameIdentifier)?.Value
                   ?? user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;
        var name = user.Identity?.Name
                   ?? user.FindFirst(ClaimTypes.Name)?.Value
                   ?? user.FindFirst(JwtRegisteredClaimNames.UniqueName)?.Value;
        var roles = user.Claims.Where(c => c.Type == ClaimTypes.Role || c.Type == "role")
                               .Select(c => c.Value)
                               .ToArray();

        return Task.FromResult(Success("Profile", new { userId = sub, userName = name, roles }));
    }

    private static string? ExtractBearer(string? authorizationHeader) =>
        authorizationHeader?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true
            ? authorizationHeader["Bearer ".Length..].Trim()
            : null;
}