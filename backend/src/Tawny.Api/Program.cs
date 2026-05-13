using System.Text.Json.Serialization;
using Hangfire;
using Hangfire.SqlServer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using Tawny.Api.Auth;
using Tawny.Api.Controllers;
using Tawny.Infrastructure;
using Tawny.Jobs;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

builder.Services.Configure<AgentJwtOptions>(builder.Configuration.GetSection("Tawny:AgentJwt"));
builder.Services.Configure<EnrollmentOptions>(builder.Configuration.GetSection("Tawny:Enrollment"));
builder.Services.Configure<RetentionOptions>(builder.Configuration.GetSection("Tawny:Retention"));
builder.Services.Configure<WebUserAuthOptions>(opt =>
{
    opt.HmacSecret = builder.Configuration["Tawny:WebUserHmacSecret"] ?? "";
});

builder.Services.AddSingleton<AgentJwtService>();
builder.Services.AddTawnyInfrastructure(builder.Configuration);

builder.Services.AddControllers()
    .AddJsonOptions(o =>
    {
        o.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.SnakeCaseLower;
        o.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter(System.Text.Json.JsonNamingPolicy.SnakeCaseLower));
    });
builder.Services.AddProblemDetails();
builder.Services.AddOpenApi();

builder.Services
    .AddAuthentication()
    .AddJwtBearer(TawnyAuthSchemes.AgentJwt, _ => { })
    .AddScheme<WebUserAuthOptions, WebUserAuthHandler>(TawnyAuthSchemes.WebUser, _ => { });

builder.Services
    .AddOptions<JwtBearerOptions>(TawnyAuthSchemes.AgentJwt)
    .Configure<AgentJwtService, Microsoft.Extensions.Options.IOptions<AgentJwtOptions>>(
        (options, jwt, agentOpts) =>
        {
            var opts = agentOpts.Value;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = opts.Issuer,
                ValidateAudience = true,
                ValidAudience = opts.Audience,
                ValidateLifetime = true,
                IssuerSigningKey = jwt.GetValidationKey(),
                ValidateIssuerSigningKey = true,
                ClockSkew = TimeSpan.FromSeconds(30),
            };
        });

builder.Services.AddAuthorization();

builder.Services.AddScoped<MarkStaleAgentsJob>();
builder.Services.AddScoped<PurgeOldEventsJob>();
builder.Services.AddScoped<CheckAgentReleasesJob>();

builder.Services.AddHangfire(cfg => cfg
    .SetDataCompatibilityLevel(CompatibilityLevel.Version_180)
    .UseSimpleAssemblyNameTypeSerializer()
    .UseRecommendedSerializerSettings()
    .UseSqlServerStorage(
        builder.Configuration.GetConnectionString("Default"),
        new SqlServerStorageOptions
        {
            PrepareSchemaIfNecessary = true,
            QueuePollInterval = TimeSpan.FromSeconds(5),
        }));
builder.Services.AddHangfireServer();

var app = builder.Build();

app.UseSerilogRequestLogging();
app.UseExceptionHandler();
app.UseStatusCodePages();

app.MapOpenApi();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.MapHangfireDashboard("/hangfire");

RecurringJob.AddOrUpdate<MarkStaleAgentsJob>(
    "mark-stale-agents", j => j.ExecuteAsync(default), Cron.Minutely);
RecurringJob.AddOrUpdate<PurgeOldEventsJob>(
    "purge-old-events", j => j.ExecuteAsync(default), "0 2 * * *");
RecurringJob.AddOrUpdate<CheckAgentReleasesJob>(
    "check-agent-releases", j => j.ExecuteAsync(default), Cron.Hourly);

app.Run();

public partial class Program;
