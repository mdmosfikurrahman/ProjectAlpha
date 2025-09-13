using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using ProjectAlpha.Application.Dto.Security;
using ProjectAlpha.Application.Services;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace ProjectAlpha.Configuration.Services;

public static class StartupConfiguration
{
    public static IServiceCollection AddStartupServices(this IServiceCollection services, IConfiguration config)
    {
        services.AddControllers(options =>
        {
            options.Filters.Add(new AuthorizeFilter());
        });


        services.AddApiVersioning(options =>
        {
            options.DefaultApiVersion = new ApiVersion(1, 0);
            options.AssumeDefaultVersionWhenUnspecified = true;
            options.ReportApiVersions = true;
            options.ApiVersionReader = new UrlSegmentApiVersionReader();
        });

        services.AddVersionedApiExplorer(options =>
        {
            options.GroupNameFormat = "'v'VVV";
            options.SubstituteApiVersionInUrl = true;
        });

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen();
        services.AddTransient<IConfigureOptions<SwaggerGenOptions>, ConfigureSwaggerOptions>();

        services.AddSingleton<IAirlineService, AirlineService>();
        services.AddSingleton<IAirportService, AirportService>();

        var jwtOptions = new JwtOptions();
        config.GetSection("Jwt").Bind(jwtOptions);
        services.AddSingleton(jwtOptions);
        
        services.AddSingleton<IUserService, InMemoryUserService>();
        services.AddSingleton<ITokenService, TokenService>();
        services.AddSingleton<ITokenBlacklist, InMemoryTokenBlacklist>();
        services.AddSingleton<IAuthService, AuthService>();

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtOptions.Key));

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.RequireHttpsMetadata = true;
                options.SaveToken = true;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = jwtOptions.Issuer,
                    ValidAudience = jwtOptions.Audience,
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ClockSkew = TimeSpan.FromSeconds(30)
                };

                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        var blacklist = context.HttpContext.RequestServices.GetRequiredService<ITokenBlacklist>();
                        var jti = context.Principal?.FindFirst("jti")?.Value;
                        if (!string.IsNullOrEmpty(jti) && blacklist.IsBlacklisted(jti))
                        {
                            context.Fail("Token has been revoked.");
                        }
                        return Task.CompletedTask;
                    }
                };
            });

        services.AddAuthorization();

        return services;
    }

    private sealed class ConfigureSwaggerOptions(IApiVersionDescriptionProvider provider)
        : IConfigureOptions<SwaggerGenOptions>
    {
        public void Configure(SwaggerGenOptions options)
        {
            foreach (var desc in provider.ApiVersionDescriptions)
            {
                options.SwaggerDoc(
                    desc.GroupName,
                    new OpenApiInfo
                    {
                        Title = $"ProjectAlpha API v{desc.ApiVersion}",
                        Version = desc.ApiVersion.ToString(),
                        Description = $"ProjectAlpha API version {desc.ApiVersion}"
                    }
                );
            }

            options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.Http,
                Scheme = "bearer",
                BearerFormat = "JWT"
            });

            options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
                    },
                    Array.Empty<string>()
                }
            });
        }
    }
}
