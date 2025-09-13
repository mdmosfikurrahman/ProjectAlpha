using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProjectAlpha.Application.Dto.Request;
using ProjectAlpha.Application.Services;

namespace ProjectAlpha.WebAPI.Controllers;

[ApiController]
[Authorize]
[ApiVersion("1.0")]
[ApiVersion("2.0")]
[Route("v{version:apiVersion}/airlines")]
public class AirlinesController(IAirlineService service) : ControllerBase
{
    [HttpGet]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> GetAll() => Ok(await service.GetAllAsync());

    [HttpGet("{id:guid}")]
    [MapToApiVersion("1.0")]
    public async Task<IActionResult> GetById(Guid id) => Ok(await service.GetByIdAsync(id));

    [HttpPost]
    [MapToApiVersion("2.0")]
    public async Task<IActionResult> Create([FromBody] AirlineRequest request) =>
        Ok(await service.CreateAsync(request));
}