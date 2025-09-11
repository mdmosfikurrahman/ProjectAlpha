namespace ProjectAlpha.Domain.Entities;

public class Airport
{
    public Guid Id { get; set; }
    public string? Code { get; set; }
    public string? IcaoCode { get; set; }
    public string? AirportName { get; set; }
}