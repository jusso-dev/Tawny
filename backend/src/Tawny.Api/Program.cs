using System.Text.Json.Serialization;
using FluentValidation;
using Hangfire;
using Hangfire.Dashboard;
using Hangfire.SqlServer;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Threading.RateLimiting;
using Tawny.Api.Auth;
using Tawny.Api.Controllers;
using Tawny.Api.Services;
using Tawny.Infrastructure;
using Tawny.Jobs;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

builder.Services.Configure<AgentJwtOptions>(builder.Configuration.GetSection("Tawny:AgentJwt"));
builder.Services.Configure<EnrollmentOptions>(builder.Configuration.GetSection("Tawny:Enrollment"));
builder.Services.Configure<RetentionOptions>(builder.Configuration.GetSection("Tawny:Retention"));
builder.Services.Configure<TelemetryBackupOptions>(builder.Configuration.GetSection("Tawny:TelemetryBackup"));
builder.Services.Configure<WazuhSinkOptions>(builder.Configuration.GetSection("Tawny:Wazuh"));
builder.Services.Configure<WebUserAuthOptions>(TawnyAuthSchemes.WebUser, opt =>
{
    opt.HmacSecret = builder.Configuration["Tawny:WebUserHmacSecret"] ?? "";
});

builder.Services.AddSingleton<AgentJwtService>();
builder.Services.AddTawnyInfrastructure(builder.Configuration);
builder.Services.AddValidatorsFromAssemblyContaining<Program>();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddScoped<AuditLogger>();
builder.Services.AddScoped<AlertRuleEvaluator>();
builder.Services.AddScoped<SigmaRuleImporter>();
builder.Services.AddSingleton<IAlertSink, WazuhAlertSink>();
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("agent-events", httpContext =>
    {
        var agentId = httpContext.User.FindFirst("agent_id")?.Value
            ?? httpContext.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";
        var tenantId = httpContext.User.FindFirst(TenantClaimExtensions.TenantIdClaim)?.Value
            ?? "default";
        return RateLimitPartition.GetTokenBucketLimiter($"{tenantId}:{agentId}", _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = 120,
            TokensPerPeriod = 120,
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            AutoReplenishment = true,
            QueueLimit = 0,
        });
    });
    options.OnRejected = async (context, ct) =>
    {
        context.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        await context.HttpContext.Response.WriteAsJsonAsync(new
        {
            error = "event_ingest_rate_limited",
            detail = "Too many telemetry ingest requests for this agent.",
        }, cancellationToken: ct);
    };
});

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
if (!builder.Configuration.GetValue<bool>("Tawny:DisableHangfire"))
{
    builder.Services.AddScoped<PurgeOldEventsJob>();
    builder.Services.AddScoped<BackupTelemetryJob>();
    builder.Services.AddHttpClient<CheckAgentReleasesJob>();

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
}

var app = builder.Build();

if (app.Configuration.GetValue<bool>("Tawny:ApplyMigrationsOnStartup"))
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<TawnyDbContext>();
    await db.Database.MigrateAsync();
}

app.UseSerilogRequestLogging();
app.UseExceptionHandler();
app.UseStatusCodePages();

app.MapOpenApi();
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();

app.MapControllers();
if (!app.Configuration.GetValue<bool>("Tawny:DisableHangfire"))
{
    app.MapHangfireDashboard("/hangfire", new DashboardOptions
    {
        Authorization = [new HangfireWebUserAuthorizationFilter()],
    });

    RecurringJob.AddOrUpdate<MarkStaleAgentsJob>(
        "mark-stale-agents", j => j.ExecuteAsync(default), Cron.Minutely);
    RecurringJob.AddOrUpdate<PurgeOldEventsJob>(
        "purge-old-events", j => j.ExecuteAsync(default), "0 2 * * *");
    RecurringJob.AddOrUpdate<BackupTelemetryJob>(
        "backup-telemetry", j => j.ExecuteAsync(default), "0 3 * * *");
    RecurringJob.AddOrUpdate<CheckAgentReleasesJob>(
        "check-agent-releases", j => j.ExecuteAsync(default), Cron.Hourly);
}

app.Run();

public partial class Program;
