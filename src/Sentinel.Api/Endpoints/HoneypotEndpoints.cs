using Sentinel.Api.Detection;
using Sentinel.Api.Monitoring;
using Sentinel.Shared;

namespace Sentinel.Api.Endpoints;

/// <summary>
/// Honeypot endpoints: URLs that attackers and scanners probe, but that no real user ever needs.
/// Any request to them is logged and raises a critical alert. They answer with believable fake
/// content so the attacker keeps going, and the fake .env plants honeytoken credentials that
/// trigger another alert if anyone tries to use them.
/// </summary>
public static class HoneypotEndpoints
{
    public static void MapHoneypotEndpoints(this IEndpointRouteBuilder app, DetectionOptions options)
    {
        foreach (var trap in HoneypotTraps.Paths)
        {
            app.Map(trap, (HttpContext http, EventQueue queue) => Trap(http, queue, options)).AllowAnonymous().ExcludeFromDescription();
            app.Map(trap + "/{**rest}", (HttpContext http, EventQueue queue) => Trap(http, queue, options)).AllowAnonymous().ExcludeFromDescription();
        }
    }

    private static IResult Trap(HttpContext http, EventQueue queue, DetectionOptions options)
    {
        http.MarkRecorded();
        http.Response.StatusCode = StatusCodes.Status200OK;
        queue.TryEnqueue(http.NewEvent(EventType.HoneypotHit));

        var path = http.Request.Path.Value ?? "";
        var honeytoken = options.Honeytokens.FirstOrDefault() ?? "backup_admin";

        if (path.StartsWith("/.env"))
            return Results.Text(
                $"""
                APP_ENV=production
                DB_HOST=10.0.12.4
                DB_USER={honeytoken}
                DB_PASSWORD=Spring2024!backup
                ADMIN_USER={honeytoken}
                ADMIN_PASSWORD=Spring2024!backup
                AWS_REGION=eu-north-1
                """, "text/plain");

        if (path.StartsWith("/.git"))
            return Results.Text("[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = git@internal-git:platform/backend.git\n", "text/plain");

        if (path.StartsWith("/wp-") || path.StartsWith("/admin") || path.StartsWith("/phpmyadmin"))
            return Results.Content(
                "<!doctype html><html><head><title>Log In</title></head><body>" +
                "<form method=\"post\"><input name=\"log\" placeholder=\"Username\"><input name=\"pwd\" type=\"password\">" +
                "<button>Log In</button></form></body></html>", "text/html");

        return Results.Json(new { status = "ok", version = "2.4.1" });
    }
}
