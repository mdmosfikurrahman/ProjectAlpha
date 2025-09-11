namespace ProjectAlpha.Application.Dto.Security;

public class JwtOptions
{
    public string Issuer { get; set; } = "ProjectAlpha";
    public string Audience { get; set; } = "ProjectAlpha.Clients";
    public string Key { get; set; } = default!;
    public int AccessTokenLifetimeMinutes { get; set; } = 60;
}