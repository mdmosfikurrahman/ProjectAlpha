using ProjectAlpha.Configuration.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddStartupServices(builder.Configuration);

var app = builder.Build();

app.UseStartupPipeline();

app.Run();