using System.Collections.Concurrent;
using ProjectAlpha.Application.Dto.Request;
using ProjectAlpha.Application.Dto.Response;
using ProjectAlpha.Domain.Entities;
using ProjectAlpha.Shared.Dto;
using static ProjectAlpha.Shared.Dto.ApiResponseHelper;

namespace ProjectAlpha.Application.Services;

public interface IAirlineService
{
    Task<StandardResponse> GetAllAsync();
    Task<StandardResponse> GetByIdAsync(Guid id);
    Task<StandardResponse> CreateAsync(AirlineRequest request);
}

public class AirlineService : IAirlineService
{
    private readonly ConcurrentDictionary<Guid, Airline> _store = new();
    private const string EntityName = "Airline";

    public AirlineService()
    {
        var emirates = new Airline { Id = Guid.NewGuid(), Code = "EK", IcaoCode = "UAE", Name = "Emirates" };
        var qatar = new Airline { Id = Guid.NewGuid(), Code = "QR", IcaoCode = "QTR", Name = "Qatar Airways" };
        _store[emirates.Id] = emirates;
        _store[qatar.Id] = qatar;
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

    public Task<StandardResponse> CreateAsync(AirlineRequest request)
    {
        var errors = new List<ErrorDetails>();

        if (string.IsNullOrWhiteSpace(request.Code))
            errors.Add(new ErrorDetails(nameof(request.Code), "Code is required."));
        if (string.IsNullOrWhiteSpace(request.Name))
            errors.Add(new ErrorDetails(nameof(request.Name), "Name is required."));

        if (errors.Count > 0)
            return Task.FromResult(ValidationError(EntityName, errors));

        var entity = new Airline
        {
            Id = Guid.NewGuid(),
            Code = request.Code.Trim(),
            IcaoCode = string.IsNullOrWhiteSpace(request.IcaoCode) ? null : request.IcaoCode.Trim(),
            Name = request.Name.Trim()
        };

        _store[entity.Id] = entity;

        return Task.FromResult(Created(EntityName, ToResponse(entity)));
    }

    private static AirlineResponse ToResponse(Airline a) => new()
    {
        Id = a.Id,
        Code = a.Code,
        IcaoCode = a.IcaoCode,
        Name = a.Name
    };
}