using Sentinel.Shared;

namespace Sentinel.Api.Data;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public required string Username { get; set; }
    public required string PasswordHash { get; set; }
    public required string Role { get; set; }
    public bool IsActive { get; set; } = true;

    // Embedded in every JWT. Changing it (deactivation, role change) instantly invalidates old tokens.
    public Guid SecurityStamp { get; set; } = Guid.NewGuid();
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    public UserDto ToDto() => new(Id, Username, Role, IsActive, CreatedAtUtc);
}

public class SecurityEvent
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public EventType Type { get; set; }
    public required string SourceIp { get; set; }
    public string? Username { get; set; }
    public string Method { get; set; } = "GET";
    public string Path { get; set; } = "";
    public int StatusCode { get; set; }
    public string? UserAgent { get; set; }

    // Feature vector fed to the anomaly model ("1;0;3.5;..."), kept so the model can be retrained on history.
    public string? Features { get; set; }
    public double? AnomalyScore { get; set; }

    public SecurityEventDto ToDto() =>
        new(Id, TimestampUtc, Type, SourceIp, Username, Method, Path, StatusCode, AnomalyScore);
}

public class Alert
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public DateTime CreatedAtUtc { get; set; }
    public Severity Severity { get; set; }
    public required string Category { get; set; }
    public required string Title { get; set; }
    public required string Description { get; set; }
    public required string SourceIp { get; set; }
    public string? Username { get; set; }
    public double RiskScore { get; set; }
    public AlertStatus Status { get; set; } = AlertStatus.Open;
    public string? HandledBy { get; set; }
    public DateTime? HandledAtUtc { get; set; }

    public AlertDto ToDto() =>
        new(Id, CreatedAtUtc, Severity, Category, Title, Description, SourceIp, Username, RiskScore, Status, HandledBy);
}

// Append-only: the API exposes no endpoint that updates or deletes audit entries.
public class AuditLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public required string Actor { get; set; }
    public required string Action { get; set; }
    public required string Target { get; set; }
    public required string SourceIp { get; set; }
    public bool Success { get; set; }

    public AuditLogDto ToDto() => new(Id, TimestampUtc, Actor, Action, Target, SourceIp, Success);
}
