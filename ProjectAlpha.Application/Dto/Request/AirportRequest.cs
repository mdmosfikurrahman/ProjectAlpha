namespace ProjectAlpha.Application.Dto.Request;

public class AirportRequest
{
    public string Code { get; set; } = default!;
    public string? IcaoCode { get; set; }
    public string AirportName { get; set; } = default!;
}