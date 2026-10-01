using Microsoft.EntityFrameworkCore;

namespace Sentinel.Api.Data;

public class SentinelDbContext(DbContextOptions<SentinelDbContext> options) : DbContext(options)
{
    public DbSet<User> Users => Set<User>();
    public DbSet<SecurityEvent> Events => Set<SecurityEvent>();
    public DbSet<Alert> Alerts => Set<Alert>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        b.Entity<User>(e =>
        {
            e.HasIndex(u => u.Username).IsUnique();
            e.Property(u => u.Username).HasMaxLength(64);
            e.Property(u => u.Role).HasMaxLength(16);
        });

        b.Entity<SecurityEvent>(e =>
        {
            e.HasIndex(x => x.TimestampUtc);
            e.HasIndex(x => new { x.Type, x.TimestampUtc });
            e.Property(x => x.SourceIp).HasMaxLength(64);
            e.Property(x => x.Username).HasMaxLength(64);
            e.Property(x => x.Method).HasMaxLength(10);
            e.Property(x => x.Path).HasMaxLength(512);
            e.Property(x => x.UserAgent).HasMaxLength(512);
            e.Property(x => x.Features).HasMaxLength(256);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(20);
        });

        b.Entity<Alert>(e =>
        {
            e.HasIndex(x => x.CreatedAtUtc);
            e.HasIndex(x => x.Status);
            e.Property(x => x.Severity).HasConversion<string>().HasMaxLength(10);
            e.Property(x => x.Status).HasConversion<string>().HasMaxLength(15);
            e.Property(x => x.Category).HasMaxLength(64);
            e.Property(x => x.Title).HasMaxLength(200);
            e.Property(x => x.Description).HasMaxLength(2000);
            e.Property(x => x.SourceIp).HasMaxLength(64);
        });

        b.Entity<AuditLog>(e =>
        {
            e.HasIndex(x => x.TimestampUtc);
            e.Property(x => x.Actor).HasMaxLength(64);
            e.Property(x => x.Action).HasMaxLength(64);
            e.Property(x => x.Target).HasMaxLength(256);
            e.Property(x => x.SourceIp).HasMaxLength(64);
        });
    }
}
