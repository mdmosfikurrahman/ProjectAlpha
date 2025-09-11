namespace ProjectAlpha.Domain.Entities;

public class Airline
{
    public Guid Id { get; set; }
    public string? Code { get; set; }
    public string? IcaoCode { get; set; }
    public string? Name { get; set; }
}