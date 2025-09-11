namespace ProjectAlpha.Application.Dto.Response;

public class AirportResponse
{
    public Guid Id { get; set; }
    public string? Code { get; set; } = default!;
    public string? IcaoCode { get; set; }
    public string? AirportName { get; set; } = default!;
}