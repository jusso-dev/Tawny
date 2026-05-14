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
        });

        b.Entity<AlertRule>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.Name).HasMaxLength(160).IsRequired();
            e.Property(r => r.ExternalId).HasMaxLength(128);
            e.Property(r => r.Description).HasColumnType("nvarchar(max)");
            e.Property(r => r.PayloadPath).HasMaxLength(256);
            e.Property(r => r.MatchValue).HasMaxLength(512);
            e.Property(r => r.SourceDefinition).HasColumnType("nvarchar(max)");
            e.HasIndex(r => new { r.IsEnabled, r.EventType });
            e.HasIndex(r => new { r.Format, r.ExternalId });
        });

        b.Entity<Alert>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Title).HasMaxLength(255).IsRequired();
            e.Property(a => a.Description).HasColumnType("nvarchar(max)");
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
            e.HasIndex(a => new { a.Status, a.CreatedAt });
            e.HasIndex(a => new { a.AgentId, a.CreatedAt });
        });

        b.Entity<ResponseAction>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.PayloadJson).HasColumnName("Payload").HasColumnType("nvarchar(max)").IsRequired();
            e.Property(a => a.ResultJson).HasColumnName("Result").HasColumnType("nvarchar(max)");
            e.HasOne(a => a.Agent)
                .WithMany()
                .HasForeignKey(a => a.AgentId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(a => new { a.AgentId, a.Status, a.RequestedAt });
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
    }
}
