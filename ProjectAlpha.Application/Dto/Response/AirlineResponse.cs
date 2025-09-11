namespace ProjectAlpha.Application.Dto.Response;

public class AirlineResponse
{
    public Guid Id { get; set; }
    public string? Code { get; set; } = default!;
    public string? IcaoCode { get; set; }
    public string? Name { get; set; } = default!;
}