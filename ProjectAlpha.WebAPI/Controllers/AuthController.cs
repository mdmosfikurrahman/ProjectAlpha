using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectAlpha.Application.Services;

namespace ProjectAlpha.WebAPI.Controllers;

[ApiController]
[ApiVersion("1.0")]
[Route("v{version:apiVersion}/auth")]
public class AuthController(IAuthService auth) : ControllerBase
{
    public record LoginRequest(string Username, string Password);

    [HttpPost("login")]
    [AllowAnonymous]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> Login([FromBody] LoginRequest req) =>
        Ok(await auth.LoginAsync(req.Username, req.Password));

    [HttpPost("logout")]
    [Authorize]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> Logout() =>
        Ok(await auth.LogoutAsync(Request.Headers.Authorization.ToString()));

    [HttpGet("me")]
    [Authorize]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> Me() =>
        Ok(await auth.MeAsync(User));
}