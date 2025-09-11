namespace ProjectAlpha.Application.Dto.Request;

public class AirlineRequest
{
    public string Code { get; set; } = default!;
    public string? IcaoCode { get; set; }
    public string Name { get; set; } = default!;
}