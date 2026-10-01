using System.Text.Json.Serialization;

namespace Sentinel.Shared;

public static class Roles
{
    public const string Admin = "Admin";
    public const string Analyst = "Analyst";
    public const string Viewer = "Viewer";

    public static readonly string[] All = [Admin, Analyst, Viewer];
}

[JsonConverter(typeof(JsonStringEnumConverter<Severity>))]
public enum Severity { Low, Medium, High, Critical }

[JsonConverter(typeof(JsonStringEnumConverter<AlertStatus>))]
public enum AlertStatus { Open, Acknowledged, Resolved }

[JsonConverter(typeof(JsonStringEnumConverter<EventType>))]
public enum EventType { LoginSuccess, LoginFailure, Request, AccessDenied, RateLimited, HoneypotHit }

public static class HubMethods
{
    public const string AlertRaised = "AlertRaised";
    public const string EventRecorded = "EventRecorded";
}

public record LoginRequest(string Username, string Password);

public record LoginResponse(string Token, DateTime ExpiresAtUtc, string Username, string Role);

public record CurrentUserDto(string Username, string Role);

public record AlertDto(
    Guid Id,
    DateTime CreatedAtUtc,
    Severity Severity,
    string Category,
    string Title,
    string Description,
    string SourceIp,
    string? Username,
    double RiskScore,
    AlertStatus Status,
    string? HandledBy);

public record SecurityEventDto(
    long Id,
    DateTime TimestampUtc,
    EventType Type,
    string SourceIp,
    string? Username,
    string Method,
    string Path,
    int StatusCode,
    double? AnomalyScore);

public record AuditLogDto(
    long Id,
    DateTime TimestampUtc,
    string Actor,
    string Action,
    string Target,
    string SourceIp,
    bool Success);

public record TimeBucketDto(DateTime BucketStartUtc, int Events, int Failures, int Alerts);

public record TopItemDto(string Label, int Count);

public record ModelStatusDto(string Name, bool Trained, int TrainingSamples, DateTime? TrainedAtUtc, double Threshold);

public record OverviewDto(
    int EventsLastHour,
    int FailedLoginsLastHour,
    int OpenAlerts,
    int CriticalOpenAlerts,
    int HoneypotHitsLast24h,
    int BlockedLastHour,
    IReadOnlyList<TimeBucketDto> Timeline,
    IReadOnlyList<TopItemDto> TopSourceIps,
    IReadOnlyList<TopItemDto> AlertsByCategory,
    IReadOnlyList<ModelStatusDto> Models);

public record UserDto(Guid Id, string Username, string Role, bool IsActive, DateTime CreatedAtUtc);

public record CreateUserRequest(string Username, string Password, string Role);

/// <summary>Trap URLs served by the API. Shared so the dashboard can list them.</summary>
public static class HoneypotTraps
{
    public static readonly string[] Paths =
    [
        "/.env",
        "/.git/config",
        "/wp-login.php",
        "/wp-admin",
        "/phpmyadmin",
        "/admin.php",
        "/server-status",
        "/api/v1/admin/backup",
        "/actuator/env",
        "/config.json",
    ];
}
