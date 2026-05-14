using Microsoft.EntityFrameworkCore;
using Tawny.Domain.Entities;

namespace Tawny.Infrastructure;

public class TawnyDbContext(DbContextOptions<TawnyDbContext> options) : DbContext(options)
{
    public DbSet<Agent> Agents => Set<Agent>();
    public DbSet<User> Users => Set<User>();
    public DbSet<EnrollmentToken> EnrollmentTokens => Set<EnrollmentToken>();
    public DbSet<TelemetryEvent> TelemetryEvents => Set<TelemetryEvent>();
    public DbSet<AlertRule> AlertRules => Set<AlertRule>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AgentRelease> AgentReleases => Set<AgentRelease>();
    public DbSet<AuditLog> AuditLog => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<Agent>(e =>
        {
            e.HasKey(a => a.Id);
            e.Property(a => a.Hostname).HasMaxLength(255).IsRequired();
            e.Property(a => a.OsVersion).HasMaxLength(64).IsRequired();
            e.Property(a => a.AgentVersion).HasMaxLength(32).IsRequired();
            e.Property(a => a.PublicIp).HasMaxLength(64);
            e.Property(a => a.TagsJson).HasColumnName("Tags").HasDefaultValue("[]");
            e.HasIndex(a => a.Hostname);
            e.HasIndex(a => a.LastHeartbeatAt);
        });

        b.Entity<User>(e =>
        {
            e.HasKey(u => u.Id);
            e.Property(u => u.Email).HasMaxLength(320).IsRequired();
            e.HasIndex(u => u.Email).IsUnique();
            e.Property(u => u.PasswordHash).HasMaxLength(512).IsRequired();
        });

        b.Entity<EnrollmentToken>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.TokenHash).HasMaxLength(128).IsRequired();
            e.HasIndex(t => t.TokenHash).IsUnique();
        });

        b.Entity<TelemetryEvent>(e =>
        {
            e.HasKey(t => t.Id);
            e.Property(t => t.Payload).HasColumnType("nvarchar(max)").IsRequired();
            e.HasOne(t => t.Agent)
                .WithMany(a => a.Events)
                .HasForeignKey(t => t.AgentId)
                .OnDelete(DeleteBehavior.Cascade);
            e.HasIndex(t => new { t.AgentId, t.EventType, t.OccurredAt })
                .IsDescending(false, false, true);
            e.HasIndex(t => t.ReceivedAt);
        });

        b.Entity<AlertRule>(e =>
        {
            e.HasKey(r => r.Id);
            e.Property(r => r.Name).HasMaxLength(160).IsRequired();
            e.Property(r => r.PayloadPath).HasMaxLength(256);
            e.Property(r => r.MatchValue).HasMaxLength(512);
            e.HasIndex(r => new { r.IsEnabled, r.EventType });
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
            e.Property(a => a.Action).HasMaxLength(64).IsRequired();
            e.Property(a => a.Target).HasMaxLength(255);
            e.Property(a => a.MetadataJson).HasColumnName("Metadata").HasColumnType("nvarchar(max)");
            e.HasIndex(a => a.OccurredAt);
        });
    }
}
