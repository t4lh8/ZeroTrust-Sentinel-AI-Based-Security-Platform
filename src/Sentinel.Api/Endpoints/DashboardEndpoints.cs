using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Data;
using Sentinel.Api.Detection;
using Sentinel.Api.Security;
using Sentinel.Shared;

namespace Sentinel.Api.Endpoints;

public static class DashboardEndpoints
{
    public static void MapDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api").RequireAuthorization(Policies.AnyRole);

        api.MapGet("/overview", GetOverview);

        api.MapGet("/alerts", async (SentinelDbContext db, AlertStatus? status, Severity? severity, int take = 100) =>
        {
            var query = db.Alerts.AsNoTracking();
            if (status is not null) query = query.Where(a => a.Status == status);
            if (severity is not null) query = query.Where(a => a.Severity == severity);
            var alerts = await query.OrderByDescending(a => a.CreatedAtUtc).Take(Math.Clamp(take, 1, 500)).ToListAsync();
            return alerts.Select(a => a.ToDto());
        });

        api.MapPost("/alerts/{id:guid}/acknowledge", (Guid id, SentinelDbContext db, AuditLogger audit) =>
            SetAlertStatus(id, AlertStatus.Acknowledged, db, audit)).RequireAuthorization(Policies.CanManageAlerts);

        api.MapPost("/alerts/{id:guid}/resolve", (Guid id, SentinelDbContext db, AuditLogger audit) =>
            SetAlertStatus(id, AlertStatus.Resolved, db, audit)).RequireAuthorization(Policies.CanManageAlerts);

        api.MapGet("/events", async (SentinelDbContext db, EventType? type, int take = 100) =>
        {
            var query = db.Events.AsNoTracking();
            if (type is not null) query = query.Where(e => e.Type == type);
            var events = await query.OrderByDescending(e => e.Id).Take(Math.Clamp(take, 1, 500)).ToListAsync();
            return events.Select(e => e.ToDto());
        });

        api.MapGet("/audit", async (SentinelDbContext db, int take = 200) =>
        {
            var logs = await db.AuditLogs.AsNoTracking().OrderByDescending(a => a.Id).Take(Math.Clamp(take, 1, 1000)).ToListAsync();
            return logs.Select(a => a.ToDto());
        }).RequireAuthorization(Policies.AdminOnly);

        var users = api.MapGroup("/users").RequireAuthorization(Policies.AdminOnly);
        users.MapGet("/", async (SentinelDbContext db) =>
            (await db.Users.AsNoTracking().OrderBy(u => u.Username).ToListAsync()).Select(u => u.ToDto()));
        users.MapPost("/", CreateUser);
        users.MapPost("/{id:guid}/deactivate", DeactivateUser);
    }

    private static async Task<IResult> SetAlertStatus(Guid id, AlertStatus status, SentinelDbContext db, AuditLogger audit)
    {
        var alert = await db.Alerts.FindAsync(id);
        if (alert is null) return Results.NotFound();

        alert.Status = status;
        alert.HandledBy = audit.CurrentUser;
        alert.HandledAtUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        await audit.LogAsync($"alert.{status.ToString().ToLowerInvariant()}", $"{alert.Id} ({alert.Title})", success: true);
        return Results.Ok(alert.ToDto());
    }

    private static async Task<IResult> CreateUser(CreateUserRequest request, SentinelDbContext db, IPasswordHasher<User> hasher, AuditLogger audit)
    {
        var username = (request.Username ?? "").Trim();
        var errors = new List<string>();
        if (!System.Text.RegularExpressions.Regex.IsMatch(username, "^[a-zA-Z0-9._-]{3,64}$"))
            errors.Add("Username must be 3-64 characters: letters, digits, '.', '_' or '-'.");
        if ((request.Password ?? "").Length < 12)
            errors.Add("Password must be at least 12 characters.");
        if (!Roles.All.Contains(request.Role))
            errors.Add($"Role must be one of: {string.Join(", ", Roles.All)}.");
        if (await db.Users.AnyAsync(u => u.Username == username))
            errors.Add("Username is already taken.");

        if (errors.Count > 0)
        {
            await audit.LogAsync("user.create", username, success: false);
            return Results.BadRequest(new { errors });
        }

        var user = new User { Username = username, Role = request.Role, PasswordHash = "" };
        user.PasswordHash = hasher.HashPassword(user, request.Password!);
        db.Users.Add(user);
        await db.SaveChangesAsync();
        await audit.LogAsync("user.create", $"{username} ({request.Role})", success: true);
        return Results.Created($"/api/users/{user.Id}", user.ToDto());
    }

    private static async Task<IResult> DeactivateUser(Guid id, SentinelDbContext db, AuditLogger audit)
    {
        var user = await db.Users.FindAsync(id);
        if (user is null) return Results.NotFound();
        if (user.Username == audit.CurrentUser) return Results.BadRequest(new { errors = new[] { "You cannot deactivate yourself." } });

        user.IsActive = false;
        user.SecurityStamp = Guid.NewGuid(); // revokes every token already issued to this user
        await db.SaveChangesAsync();
        await audit.LogAsync("user.deactivate", user.Username, success: true);
        return Results.Ok(user.ToDto());
    }

    private static async Task<OverviewDto> GetOverview(SentinelDbContext db, AnomalyModels models)
    {
        var now = DateTime.UtcNow;
        var hourAgo = now.AddHours(-1);
        var dayAgo = now.AddDays(-1);

        var recent = await db.Events.AsNoTracking()
            .Where(e => e.TimestampUtc > hourAgo)
            .Select(e => new { e.TimestampUtc, e.Type, e.SourceIp })
            .ToListAsync();
        var recentAlerts = await db.Alerts.AsNoTracking()
            .Where(a => a.CreatedAtUtc > hourAgo)
            .Select(a => a.CreatedAtUtc)
            .ToListAsync();

        // 12 five-minute buckets covering the last hour.
        var bucketSize = TimeSpan.FromMinutes(5);
        var firstBucket = new DateTime(now.Ticks - now.Ticks % bucketSize.Ticks, DateTimeKind.Utc) - 11 * bucketSize;
        var timeline = Enumerable.Range(0, 12).Select(i =>
        {
            var start = firstBucket + i * bucketSize;
            var end = start + bucketSize;
            var inBucket = recent.Where(e => e.TimestampUtc >= start && e.TimestampUtc < end).ToList();
            return new TimeBucketDto(start, inBucket.Count,
                inBucket.Count(e => e.Type is EventType.LoginFailure or EventType.AccessDenied or EventType.RateLimited or EventType.HoneypotHit),
                recentAlerts.Count(t => t >= start && t < end));
        }).ToList();

        var topIps = recent
            .Where(e => e.Type != EventType.Request && e.Type != EventType.LoginSuccess)
            .GroupBy(e => e.SourceIp)
            .Select(g => new TopItemDto(g.Key, g.Count()))
            .OrderByDescending(x => x.Count).Take(6).ToList();

        var categories = await db.Alerts.AsNoTracking()
            .Where(a => a.CreatedAtUtc > dayAgo)
            .GroupBy(a => a.Category)
            .Select(g => new TopItemDto(g.Key, g.Count()))
            .ToListAsync();

        var openAlerts = await db.Alerts.CountAsync(a => a.Status == AlertStatus.Open);
        var criticalOpen = await db.Alerts.CountAsync(a => a.Status == AlertStatus.Open && a.Severity == Severity.Critical);
        var honeypotHits = await db.Events.CountAsync(e => e.Type == EventType.HoneypotHit && e.TimestampUtc > dayAgo);

        return new OverviewDto(
            EventsLastHour: recent.Count,
            FailedLoginsLastHour: recent.Count(e => e.Type == EventType.LoginFailure),
            OpenAlerts: openAlerts,
            CriticalOpenAlerts: criticalOpen,
            HoneypotHitsLast24h: honeypotHits,
            BlockedLastHour: recent.Count(e => e.Type is EventType.AccessDenied or EventType.RateLimited),
            Timeline: timeline,
            TopSourceIps: topIps,
            AlertsByCategory: categories.OrderByDescending(c => c.Count).ToList(),
            Models: models.All.Select(m => new ModelStatusDto(m.Name, m.IsTrained, m.TrainingSamples, m.TrainedAtUtc, m.Threshold)).ToList());
    }
}
