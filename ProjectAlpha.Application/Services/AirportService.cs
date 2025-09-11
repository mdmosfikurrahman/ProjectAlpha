using System.Collections.Concurrent;
using ProjectAlpha.Application.Dto.Request;
using ProjectAlpha.Application.Dto.Response;
using ProjectAlpha.Domain.Entities;
using ProjectAlpha.Shared.Dto;
using static ProjectAlpha.Shared.Dto.ApiResponseHelper;

namespace ProjectAlpha.Application.Services;

public interface IAirportService
{
    Task<StandardResponse> GetAllAsync();
    Task<StandardResponse> GetByIdAsync(Guid id);
    Task<StandardResponse> CreateAsync(AirportRequest request);
}

public class AirportService : IAirportService
{
    private readonly ConcurrentDictionary<Guid, Airport> _store = new();
    private const string EntityName = "Airport";

    public AirportService()
    {
        var dhaka = new Airport { Id = Guid.NewGuid(), Code = "DAC", IcaoCode = "VGHS", AirportName = "Hazrat Shahjalal International Airport" };
        var jfk   = new Airport { Id = Guid.NewGuid(), Code = "JFK", IcaoCode = "KJFK", AirportName = "John F. Kennedy International Airport" };
        _store[dhaka.Id] = dhaka;
        _store[jfk.Id]   = jfk;
    }

    public Task<StandardResponse> GetAllAsync()
    {
        var list = _store.Values.Select(ToResponse).ToList();
        return Task.FromResult(list.Count == 0 ? NotFound($"{EntityName}s") : Success($"{EntityName}s", list));
    }

    public Task<StandardResponse> GetByIdAsync(Guid id)
    {
        return Task.FromResult(!_store.TryGetValue(id, out var entity)
            ? NotFound($"{EntityName} with Id {id}")
            : Success(EntityName, ToResponse(entity)));
    }

    public Task<StandardResponse> CreateAsync(AirportRequest request)
    {
        var errors = new List<ErrorDetails>();

        if (string.IsNullOrWhiteSpace(request.Code))
            errors.Add(new ErrorDetails(nameof(request.Code), "Code is required."));
        if (string.IsNullOrWhiteSpace(request.AirportName))
            errors.Add(new ErrorDetails(nameof(request.AirportName), "AirportName is required."));

        if (errors.Count > 0)
            return Task.FromResult(ValidationError(EntityName, errors));

        var entity = new Airport
        {
            Id = Guid.NewGuid(),
            Code = request.Code.Trim(),
            IcaoCode = string.IsNullOrWhiteSpace(request.IcaoCode) ? null : request.IcaoCode.Trim(),
            AirportName = request.AirportName.Trim()
        };

        _store[entity.Id] = entity;

        return Task.FromResult(Created(EntityName, ToResponse(entity)));
    }

    private static AirportResponse ToResponse(Airport a) => new()
    {
        Id = a.Id,
        Code = a.Code,
        IcaoCode = a.IcaoCode,
        AirportName = a.AirportName
    };
}
