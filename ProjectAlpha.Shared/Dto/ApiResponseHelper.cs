namespace ProjectAlpha.Shared.Dto;

public static class ApiResponseHelper
{
    public static StandardResponse Success(string entityName, object? data = null) =>
        new()
        {
            IsSuccess = true,
            StatusCode = StatusCodes.Success200,
            Message = $"{entityName} retrieved successfully.",
            Data = data
        };

    public static StandardResponse Created(string entityName, object? data = null) =>
        new()
        {
            IsSuccess = true,
            StatusCode = StatusCodes.Created201,
            Message = $"{entityName} created successfully.",
            Data = data
        };
    
    public static StandardResponse NotFound(string entityName, object? data = null) =>
        new()
        {
            IsSuccess = true, StatusCode = StatusCodes.NotFound404, Message = $"{entityName} not found.", Data = data
        };

    public static StandardResponse ValidationError(string entityName, List<ErrorDetails> errorList) =>
        new()
        {
            IsSuccess = false,
            StatusCode = StatusCodes.UnprocessableEntity422,
            Message = errorList.FirstOrDefault()?.Message ?? string.Empty,
            Errors = errorList
        };
    
    public static StandardResponse Forbidden(string entityName, string? customMessage = null, object? data = null) =>
        new()
        {
            IsSuccess = false,
            StatusCode = StatusCodes.Forbidden403,
            Message = customMessage ?? $"{entityName} access is forbidden.",
            Data = data
        };
    
    public static StandardResponse Unauthorized(string entity, string? message = null, object? data = null)
        => new()
        {
            IsSuccess = false,
            StatusCode = StatusCodes.Unauthorized401,
            Message = message ?? $"{entity}: You are not authorized.",
            Data = data
        };
}