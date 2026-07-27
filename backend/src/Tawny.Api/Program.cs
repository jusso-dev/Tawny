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
using Tawny.Infrastructure.Hunting;
using Tawny.Infrastructure.ThreatIntel;
using Tawny.Jobs;
using Tawny.Jobs.Cloud;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((ctx, cfg) => cfg.ReadFrom.Configuration(ctx.Configuration));

builder.Services.Configure<AgentJwtOptions>(builder.Configuration.GetSection("Tawny:AgentJwt"));
builder.Services.Configure<EnrollmentOptions>(builder.Configuration.GetSection("Tawny:Enrollment"));
builder.Services.Configure<RetentionOptions>(builder.Configuration.GetSection("Tawny:Retention"));
builder.Services.Configure<TelemetryBackupOptions>(builder.Configuration.GetSection("Tawny:TelemetryBackup"));
builder.Services.Configure<WazuhSinkOptions>(builder.Configuration.GetSection("Tawny:Wazuh"));
builder.Services.Configure<SlackSinkOptions>(builder.Configuration.GetSection("Tawny:Slack"));
builder.Services.Configure<SentinelSinkOptions>(builder.Configuration.GetSection("Tawny:Sentinel"));
builder.Services.Configure<KelpieSinkOptions>(builder.Configuration.GetSection("Tawny:Kelpie"));
builder.Services.Configure<UniFiKelpieOptions>(builder.Configuration.GetSection("Tawny:Kelpie"));
builder.Services.Configure<TawnySocSinkOptions>(builder.Configuration.GetSection("Tawny:TawnySoc"));
builder.Services.Configure<ReputationOptions>(builder.Configuration.GetSection("Tawny:Reputation"));
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
builder.Services.AddScoped<IocRuleImporter>();
builder.Services.AddScoped<ExposureRuleImporter>();
builder.Services.AddScoped<ThreatIntelLookupService>();
builder.Services.AddSingleton<HuntQueryParser>();
builder.Services.AddScoped<HuntExecutor>();
builder.Services.AddScoped<SuppressionEvaluator>();
builder.Services.AddSingleton<SequenceRuleEvaluator>();
builder.Services.AddSingleton<RuleTestHarness>();
builder.Services.AddSingleton<AgentEventBroker>();
builder.Services.AddHttpClient<ThreatIntelFetcher>();
builder.Services.AddHttpClient<ReputationEnricher>();
builder.Services.AddSingleton<WazuhAlertSink>();
builder.Services.AddHttpClient<SlackAlertSink>();
builder.Services.AddHttpClient<TawnySocAlertSink>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpClient<TawnySocTelemetrySink>()
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
builder.Services.AddHttpClient<IAzureMonitorTokenProvider, AzureMonitorTokenProvider>();
builder.Services.AddHttpClient<AzureMonitorLogsIngestionClient>();
builder.Services.AddSingleton<SentinelAlertSink>();
builder.Services.AddHttpClient<KelpieAlertSink>();
builder.Services.AddScoped<UniFiConnector>();
builder.Services.AddScoped<ICloudLogProvider, AwsCloudLogProvider>();
builder.Services.AddScoped<ICloudLogProvider, AzureMonitorLogProvider>();
builder.Services.AddScoped<CloudHuntCoordinator>();
builder.Services.AddSingleton<SentinelTelemetrySink>();
builder.Services.AddSingleton<ITelemetrySink, CompositeTelemetrySink>();
builder.Services.AddScoped<IAlertSink, CompositeAlertSink>();
builder.Services.AddRateLimiter(options =>
{
    options.AddPolicy("agent-enrollment", httpContext =>
    {
        var remoteIp = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        return RateLimitPartition.GetFixedWindowLimiter(remoteIp, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 10,
            Window = TimeSpan.FromMinutes(1),
            AutoReplenishment = true,
            QueueLimit = 0,
        });
    });
    options.AddPolicy("agent-heartbeat", httpContext =>
    {
        var agentId = httpContext.User.FindFirst("agent_id")?.Value
            ?? httpContext.Connection.RemoteIpAddress?.ToString()
            ?? "anonymous";
        return RateLimitPartition.GetTokenBucketLimiter(agentId, _ => new TokenBucketRateLimiterOptions
        {
            TokenLimit = 12,
            TokensPerPeriod = 12,
            ReplenishmentPeriod = TimeSpan.FromMinutes(1),
            AutoReplenishment = true,
            QueueLimit = 0,
        });
    });
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
            error = "agent_request_rate_limited",
            detail = "Too many agent requests.",
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
    .AddScheme<WebUserAuthOptions, WebUserAuthHandler>(TawnyAuthSchemes.WebUser, _ => { })
    .AddScheme<ApiTokenAuthOptions, ApiTokenAuthHandler>(TawnyAuthSchemes.ApiToken, _ => { });

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
    builder.Services.AddScoped<ScheduledHuntsJob>();
    builder.Services.AddScoped<ThreatIntelFeedsJob>();
    builder.Services.AddScoped<ReputationEnrichmentJob>();
    builder.Services.AddScoped<UniFiThreatIntelJob>();
    builder.Services.AddScoped<CloudMonitoringJob>();
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
    RecurringJob.AddOrUpdate<ScheduledHuntsJob>(
        "scheduled-hunts", j => j.ExecuteAsync(default), "*/5 * * * *");
    RecurringJob.AddOrUpdate<ThreatIntelFeedsJob>(
        "threat-intel-feeds", j => j.ExecuteAsync(default), "*/10 * * * *");
    RecurringJob.AddOrUpdate<ReputationEnrichmentJob>(
        "reputation-enrichment", j => j.ExecuteAsync(default), "*/5 * * * *");
    RecurringJob.AddOrUpdate<UniFiThreatIntelJob>(
        "unifi-threat-intel", j => j.ExecuteAsync(default), Cron.Minutely);
    RecurringJob.AddOrUpdate<CloudMonitoringJob>(
        "cloud-monitoring", j => j.ExecuteAsync(default), Cron.Minutely);
}

app.Run();

public partial class Program;
