using Microsoft.EntityFrameworkCore;
using Tawny.Domain;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure;

public class TawnyDbContext(DbContextOptions<TawnyDbContext> options) : DbContext(options)
{
    public DbSet<Agent> Agents => Set<Agent>();
    public DbSet<Tenant> Tenants => Set<Tenant>();
    public DbSet<User> Users => Set<User>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<TelemetryEvent> TelemetryEvents => Set<TelemetryEvent>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<ResponseAction> ResponseActions => Set<ResponseAction>();
    public DbSet<AgentRelease> AgentReleases => Set<AgentRelease>();
    public DbSet<AuditLog> AuditLog => Set<AuditLog>();
    public DbSet<SavedHunt> SavedHunts => Set<SavedHunt>();
    public DbSet<HuntRun> HuntRuns => Set<HuntRun>();
    public DbSet<SuppressionRule> SuppressionRules => Set<SuppressionRule>();
    public DbSet<ApiToken> ApiTokens => Set<ApiToken>();
    public DbSet<ThreatIntelFeed> ThreatIntelFeeds => Set<ThreatIntelFeed>();
    public DbSet<ReputationCacheEntry> ReputationCache => Set<ReputationCacheEntry>();
    public DbSet<Case> Cases => Set<Case>();
    public DbSet<CaseAlert> CaseAlerts => Set<CaseAlert>();
    public DbSet<CaseNote> CaseNotes => Set<CaseNote>();
    public DbSet<UniFiIntegration> UniFiIntegrations => Set<UniFiIntegration>();
    public DbSet<UniFiEventMatch> UniFiEventMatches => Set<UniFiEventMatch>();
    public DbSet<CloudConnection> CloudConnections => Set<CloudConnection>();
    public DbSet<CloudHunt> CloudHunts => Set<CloudHunt>();
    public DbSet<CloudHuntRun> CloudHuntRuns => Set<CloudHuntRun>();
    public DbSet<CloudFinding> CloudFindings => Set<CloudFinding>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Tenant>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.Slug).HasMaxLength(64).IsRequired();
            e.Property(t => t.Name).HasMaxLength(128).IsRequired();
            e.HasIndex(t => t.Slug).IsUnique();
            e.HasData(new Tenant
            {
                Id = TenantDefaults.DefaultTenantId,
                Slug = TenantDefaults.DefaultTenantSlug,
                Name = TenantDefaults.DefaultTenantName,
                CreatedAt = DateTimeOffset.UnixEpoch,
            });
        });

        b.Entity<Agent>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(a => a.Hostname).HasMaxLength(255).IsRequired();
            e.Property(a => a.OsVersion).HasMaxLength(64).IsRequired();
            e.Property(a => a.AgentVersion).HasMaxLength(32).IsRequired();
            e.Property(a => a.PublicIp).HasMaxLength(64);
            e.Property(a => a.TagsJson).HasColumnName("Tags").HasDefaultValue("[]");
            e.Property(a => a.CredentialVersion).HasDefaultValue(1);
            e.Property(a => a.LastTelemetrySequence).HasDefaultValue(0L);
            e.Property(a => a.DevicePublicKey).HasMaxLength(128);
            e.HasOne(a => a.Tenant)
                .WithMany(t => t.Agents)
                .HasForeignKey(a => a.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(a => new { a.TenantId, a.Hostname });
            e.HasIndex(a => new { a.TenantId, a.LastHeartbeatAt });
        });

        b.Entity<User>(e =>
        {
            e.HasKey(u => u.Id);
            e.Property(u => u.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(u => u.Email).HasMaxLength(320).IsRequired();
            e.HasOne(u => u.Tenant)
                .WithMany(t => t.Users)
                .HasForeignKey(u => u.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(u => new { u.TenantId, u.Email }).IsUnique();
            e.Property(u => u.PasswordHash).HasMaxLength(512).IsRequired();
        });

        b.Entity<EnrollmentToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
            e.Property(t => t.UsedAt).IsConcurrencyToken();
            e.HasOne(t => t.Tenant)
                .WithMany(t => t.EnrollmentTokens)
                .HasForeignKey(t => t.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.HasIndex(t => new { t.TenantId, t.CreatedAt });
        });

        b.Entity<TelemetryEvent>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(t => t.Payload).HasColumnType("nvarchar(max)").IsRequired();
            e.Property(t => t.PayloadDigest).HasMaxLength(64);
            e.HasOne(t => t.Tenant)
                .WithMany(t => t.TelemetryEvents)
                .HasForeignKey(t => t.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(t => t.Agent)
                .WithMany(a => a.Events)
                .HasForeignKey(t => t.AgentId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(t => new { t.TenantId, t.AgentId, t.EventType, t.OccurredAt })
                .IsDescending(false, false, false, true);
            e.HasIndex(t => new { t.TenantId, t.ReceivedAt });
            e.HasIndex(t => new { t.TenantId, t.AgentId, t.ClientEventId })
                .IsUnique()
                .HasFilter("[ClientEventId] IS NOT NULL");
            e.HasIndex(t => new { t.TenantId, t.AgentId, t.BatchId });
            e.HasIndex(t => new { t.TenantId, t.AgentId, t.SequenceNumber });
        });

        b.Entity<AlertRule>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(r => r.Name).HasMaxLength(160).IsRequired();
            e.Property(r => r.ExternalId).HasMaxLength(128);
            e.Property(r => r.Description).HasColumnType("nvarchar(max)");
            e.Property(r => r.PayloadPath).HasMaxLength(256);
            e.Property(r => r.MatchValue).HasMaxLength(512);
            e.Property(r => r.SourceDefinition).HasColumnType("nvarchar(max)");
            e.Property(r => r.CompiledExpressionJson).HasColumnName("CompiledExpression").HasColumnType("nvarchar(max)");
            e.Property(r => r.MitreTechniquesJson).HasColumnName("MitreTechniques").HasColumnType("nvarchar(max)");
            e.HasOne(r => r.Tenant)
                .WithMany()
                .HasForeignKey(r => r.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(r => new { r.TenantId, r.IsEnabled, r.EventType });
            e.HasIndex(r => new { r.TenantId, r.Format, r.ExternalId });
        });

        b.Entity<Alert>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(a => a.Title).HasMaxLength(255).IsRequired();
            e.Property(a => a.Description).HasColumnType("nvarchar(max)");
            e.Property(a => a.EnrichmentJson).HasColumnName("Enrichment").HasColumnType("nvarchar(max)");
            e.Property(a => a.SlackNotificationError).HasMaxLength(1024);
            e.Property(a => a.SentinelNotificationError).HasMaxLength(1024);
            e.Property(a => a.KelpieNotificationError).HasMaxLength(1024);
            e.Property(a => a.KelpieCaseId).HasMaxLength(128);
            e.Property(a => a.KelpieCaseNumber).HasMaxLength(64);
            e.HasOne(a => a.Tenant)
                .WithMany()
                .HasForeignKey(a => a.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(a => a.AlertRule)
                .WithMany(r => r.Alerts)
                .HasForeignKey(a => a.AlertRuleId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(a => a.Agent)
                .WithMany()
                .HasForeignKey(a => a.AgentId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(a => a.TelemetryEvent)
                .WithMany()
                .HasForeignKey(a => a.TelemetryEventId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(a => new { a.TenantId, a.Status, a.CreatedAt });
            e.HasIndex(a => new { a.TenantId, a.AgentId, a.CreatedAt });
        });

        b.Entity<ResponseAction>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(a => a.PayloadJson).HasColumnName("Payload").HasColumnType("nvarchar(max)").IsRequired();
            e.Property(a => a.ResultJson).HasColumnName("Result").HasColumnType("nvarchar(max)");
            e.Property(a => a.PayloadHash).HasMaxLength(64);
            e.Property(a => a.ExecutionTokenHash).HasMaxLength(64);
            e.Property(a => a.IdempotencyKey).HasMaxLength(128);
            e.HasOne(a => a.Agent)
                .WithMany()
                .HasForeignKey(a => a.AgentId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(a => new { a.AgentId, a.Status, a.RequestedAt });
            e.HasIndex(a => new { a.TenantId, a.AgentId, a.IdempotencyKey });
        });

        b.Entity<AgentRelease>(e =>
        {
            e.HasKey(r => new { r.Version, r.Platform });
            e.Property(r => r.Version).HasMaxLength(32);
            e.Property(r => r.Platform).HasMaxLength(32);
            e.Property(r => r.DownloadUrl).HasMaxLength(1024).IsRequired();
            e.Property(r => r.Sha256).HasMaxLength(128).IsRequired();
            e.HasIndex(r => new { r.Platform, r.IsLatest });
        });

        b.Entity<AuditLog>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(a => a.Action).HasMaxLength(64).IsRequired();
            e.Property(a => a.Target).HasMaxLength(255);
            e.Property(a => a.MetadataJson).HasColumnName("Metadata").HasColumnType("nvarchar(max)");
            e.HasOne(a => a.Tenant)
                .WithMany(t => t.AuditLog)
                .HasForeignKey(a => a.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(a => new { a.TenantId, a.OccurredAt });
        });

        b.Entity<SavedHunt>(e =>
        {
            e.HasKey(h => h.Id);
            e.Property(h => h.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(h => h.Name).HasMaxLength(160).IsRequired();
            e.Property(h => h.Description).HasColumnType("nvarchar(max)");
            e.Property(h => h.Query).HasColumnType("nvarchar(max)").IsRequired();
            e.Property(h => h.ScheduleCron).HasMaxLength(64);
            e.Property(h => h.MitreTechniquesJson).HasColumnName("MitreTechniques").HasColumnType("nvarchar(max)");
            e.HasOne(h => h.Tenant)
                .WithMany(t => t.SavedHunts)
                .HasForeignKey(h => h.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(h => new { h.TenantId, h.Name }).IsUnique();
            e.HasIndex(h => new { h.TenantId, h.IsScheduled });
        });

        b.Entity<HuntRun>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(r => r.ErrorMessage).HasMaxLength(1024);
            e.HasOne(r => r.SavedHunt)
                .WithMany(h => h.Runs)
                .HasForeignKey(r => r.SavedHuntId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(r => new { r.TenantId, r.SavedHuntId, r.StartedAt })
                .IsDescending(false, false, true);
        });

        b.Entity<SuppressionRule>(e =>
        {
            e.HasKey(s => s.Id);
            e.Property(s => s.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(s => s.Name).HasMaxLength(160).IsRequired();
            e.Property(s => s.Reason).HasColumnType("nvarchar(max)");
            e.Property(s => s.PayloadPath).HasMaxLength(256);
            e.Property(s => s.MatchValue).HasMaxLength(512);
            e.HasOne(s => s.Tenant)
                .WithMany(t => t.SuppressionRules)
                .HasForeignKey(s => s.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(s => s.AlertRule)
                .WithMany()
                .HasForeignKey(s => s.AlertRuleId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(s => s.Agent)
                .WithMany()
                .HasForeignKey(s => s.AgentId)
                .OnDelete(DeleteBehavior.SetNull);
            e.HasIndex(s => new { s.TenantId, s.IsEnabled });
            e.HasIndex(s => new { s.AlertRuleId });
        });

        b.Entity<ApiToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(t => t.Name).HasMaxLength(160).IsRequired();
            e.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
            e.Property(t => t.TokenPrefix).HasMaxLength(16).IsRequired();
            e.HasOne(t => t.Tenant)
                .WithMany(t => t.ApiTokens)
                .HasForeignKey(t => t.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(t => t.TokenHash).IsUnique();
            e.HasIndex(t => new { t.TenantId, t.CreatedAt });
        });

        b.Entity<ThreatIntelFeed>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(t => t.Name).HasMaxLength(160).IsRequired();
            e.Property(t => t.Url).HasMaxLength(1024).IsRequired();
            e.Property(t => t.AuthHeaderName).HasMaxLength(64);
            e.Property(t => t.AuthHeaderValueEncrypted).HasMaxLength(1024);
            e.Property(t => t.LastError).HasMaxLength(2048);
            e.Property(t => t.Etag).HasMaxLength(256);
            e.HasOne(t => t.Tenant)
                .WithMany(t => t.ThreatIntelFeeds)
                .HasForeignKey(t => t.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(t => new { t.TenantId, t.IsEnabled });
        });

        b.Entity<ReputationCacheEntry>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(r => r.IndicatorKind).HasMaxLength(32).IsRequired();
            e.Property(r => r.IndicatorValue).HasMaxLength(512).IsRequired();
            e.Property(r => r.DetailJson).HasColumnType("nvarchar(max)").IsRequired();
            e.HasIndex(r => new { r.TenantId, r.Provider, r.IndicatorKind, r.IndicatorValue }).IsUnique();
            e.HasIndex(r => r.ExpiresAt);
        });

        b.Entity<Case>(e =>
        {
            e.HasKey(c => c.Id);
            e.Property(c => c.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(c => c.Title).HasMaxLength(255).IsRequired();
            e.Property(c => c.Summary).HasColumnType("nvarchar(max)");
            e.Property(c => c.MitreTechniquesJson).HasColumnName("MitreTechniques").HasColumnType("nvarchar(max)");
            e.HasOne(c => c.Tenant)
                .WithMany(t => t.Cases)
                .HasForeignKey(c => c.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(c => new { c.TenantId, c.Status, c.CreatedAt });
        });

        b.Entity<CaseAlert>(e =>
        {
            e.HasKey(ca => ca.Id);
            e.HasOne(ca => ca.Case)
                .WithMany(c => c.CaseAlerts)
                .HasForeignKey(ca => ca.CaseId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasOne(ca => ca.Alert)
                .WithMany()
                .HasForeignKey(ca => ca.AlertId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(ca => new { ca.CaseId, ca.AlertId }).IsUnique();
        });

        b.Entity<CaseNote>(e =>
        {
            e.HasKey(n => n.Id);
            e.Property(n => n.Body).HasColumnType("nvarchar(max)").IsRequired();
            e.HasOne(n => n.Case)
                .WithMany(c => c.Notes)
                .HasForeignKey(n => n.CaseId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(n => new { n.CaseId, n.CreatedAt });
        });

        b.Entity<UniFiIntegration>(e =>
        {
            e.HasKey(i => i.Id);
            e.Property(i => i.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(i => i.BaseUrl).HasMaxLength(1024).IsRequired();
            e.Property(i => i.EventsUrl).HasMaxLength(2048).IsRequired();
            e.Property(i => i.ApiKeyHeader).HasMaxLength(64).IsRequired();
            e.Property(i => i.ApiKeyEncrypted).HasColumnType("nvarchar(max)").IsRequired();
            e.Property(i => i.RecordsPath).HasMaxLength(256);
            e.Property(i => i.NetworkVersion).HasMaxLength(64);
            e.Property(i => i.LastError).HasMaxLength(2048);
            e.HasOne(i => i.Tenant)
                .WithMany(t => t.UniFiIntegrations)
                .HasForeignKey(i => i.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(i => i.TenantId).IsUnique();
            e.HasIndex(i => new { i.IsEnabled, i.LastRunAt });
        });

        b.Entity<UniFiEventMatch>(e =>
        {
            e.HasKey(m => m.Id);
            e.Property(m => m.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(m => m.DedupeKey).HasMaxLength(64).IsRequired();
            e.Property(m => m.EventReference).HasMaxLength(255).IsRequired();
            e.Property(m => m.MatchedValuesJson).HasColumnType("nvarchar(max)").IsRequired();
            e.Property(m => m.KelpieCaseId).HasMaxLength(128).IsRequired();
            e.Property(m => m.KelpieCaseNumber).HasMaxLength(64);
            e.HasOne(m => m.Tenant)
                .WithMany(t => t.UniFiEventMatches)
                .HasForeignKey(m => m.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(m => m.UniFiIntegration)
                .WithMany(i => i.EventMatches)
                .HasForeignKey(m => m.UniFiIntegrationId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(m => new { m.TenantId, m.DedupeKey }).IsUnique();
            e.HasIndex(m => new { m.UniFiIntegrationId, m.CreatedAt });
        });

        b.Entity<CloudConnection>(e =>
        {
            e.HasKey(c => c.Id);
            e.Property(c => c.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(c => c.Name).HasMaxLength(160).IsRequired();
            e.Property(c => c.ExternalAccountId).HasMaxLength(128).IsRequired();
            e.Property(c => c.ConfigurationJson).HasColumnName("Configuration").HasColumnType("nvarchar(max)").IsRequired();
            e.Property(c => c.CredentialEncrypted).HasColumnType("nvarchar(max)");
            e.Property(c => c.LastError).HasMaxLength(2048);
            e.HasOne(c => c.Tenant)
                .WithMany(t => t.CloudConnections)
                .HasForeignKey(c => c.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasIndex(c => new { c.TenantId, c.Provider, c.Name }).IsUnique();
            e.HasIndex(c => new { c.TenantId, c.IsEnabled });
        });

        b.Entity<CloudHunt>(e =>
        {
            e.HasKey(h => h.Id);
            e.Property(h => h.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(h => h.Name).HasMaxLength(160).IsRequired();
            e.Property(h => h.Description).HasColumnType("nvarchar(max)");
            e.Property(h => h.QueryJson).HasColumnName("Query").HasColumnType("nvarchar(max)").IsRequired();
            e.Property(h => h.MitreTechniquesJson).HasColumnName("MitreTechniques").HasColumnType("nvarchar(max)");
            e.Property(h => h.LastError).HasMaxLength(2048);
            e.HasOne(h => h.Tenant)
                .WithMany(t => t.CloudHunts)
                .HasForeignKey(h => h.TenantId)
                .OnDelete(DeleteBehavior.Restrict);
            e.HasOne(h => h.CloudConnection)
                .WithMany(c => c.Hunts)
                .HasForeignKey(h => h.CloudConnectionId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(h => new { h.TenantId, h.Name }).IsUnique();
            e.HasIndex(h => new { h.TenantId, h.IsEnabled, h.LastRunAt });
        });

        b.Entity<CloudHuntRun>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(r => r.ErrorMessage).HasMaxLength(2048);
            e.HasOne(r => r.CloudHunt)
                .WithMany(h => h.Runs)
                .HasForeignKey(r => r.CloudHuntId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(r => new { r.TenantId, r.CloudHuntId, r.StartedAt })
                .IsDescending(false, false, true);
        });

        b.Entity<CloudFinding>(e =>
        {
            e.HasKey(f => f.Id);
            e.Property(f => f.TenantId).HasDefaultValue(TenantDefaults.DefaultTenantId);
            e.Property(f => f.ProviderEventId).HasMaxLength(512).IsRequired();
            e.Property(f => f.DedupeKey).HasMaxLength(64).IsRequired();
            e.Property(f => f.Title).HasMaxLength(255).IsRequired();
            e.Property(f => f.Actor).HasMaxLength(1024);
            e.Property(f => f.Resource).HasMaxLength(2048);
            e.Property(f => f.EvidenceJson).HasColumnName("Evidence").HasColumnType("nvarchar(max)").IsRequired();
            e.HasOne(f => f.CloudHunt)
                .WithMany(h => h.Findings)
                .HasForeignKey(f => f.CloudHuntId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(f => new { f.CloudHuntId, f.DedupeKey }).IsUnique();
            e.HasIndex(f => new { f.TenantId, f.Status, f.OccurredAt })
                .IsDescending(false, false, true);
        });
    }
}
