using System.Net;
using Sentinel.Api.Data;
using Sentinel.Shared;

namespace Sentinel.Api.Monitoring;

public static class HttpContextExtensions
{
    private const string RecordedKey = "sentinel.recorded";

    public static string ClientIp(this HttpContext context)
    {
        var ip = context.Connection.RemoteIpAddress;
        if (ip is null) return "unknown";
        return (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip).ToString();
    }

    /// <summary>Marks the request as already recorded by its endpoint (login, honeypot), so the middleware skips it.</summary>
    public static void MarkRecorded(this HttpContext context) => context.Items[RecordedKey] = true;

    public static bool IsRecorded(this HttpContext context) => context.Items.ContainsKey(RecordedKey);

    public static SecurityEvent NewEvent(this HttpContext context, EventType type, string? username = null) => new()
    {
        TimestampUtc = DateTime.UtcNow,
        Type = type,
        SourceIp = context.ClientIp(),
        Username = username ?? context.User.Identity?.Name,
        Method = context.Request.Method,
        Path = Truncate(context.Request.Path.Value ?? "/", 512),
        StatusCode = context.Response.StatusCode,
        UserAgent = Truncate(context.Request.Headers.UserAgent.ToString(), 512),
    };

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}

/// <summary>
/// Records every API call and every suspicious response (401/403/404/429) as a security event.
/// Static Blazor files are skipped unless they fail, so the event stream stays meaningful.
/// </summary>
public sealed class RequestMonitoringMiddleware(RequestDelegate next, EventQueue queue)
{
    public async Task InvokeAsync(HttpContext context)
    {
        await next(context);

        if (context.IsRecorded()) return;

        var path = context.Request.Path;
        var status = context.Response.StatusCode;
        var isApi = path.StartsWithSegments("/api");
        var suspicious = status is (int)HttpStatusCode.Unauthorized or (int)HttpStatusCode.Forbidden
            or (int)HttpStatusCode.NotFound or (int)HttpStatusCode.TooManyRequests;

        if (!isApi && !suspicious) return;
        if (path.StartsWithSegments("/hubs") && status != 401) return;

        var type = status switch
        {
            401 or 403 => EventType.AccessDenied,
            429 => EventType.RateLimited,
            _ => EventType.Request,
        };
        queue.TryEnqueue(context.NewEvent(type));
    }
}

/// <summary>Defense-in-depth browser hardening headers.</summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    // Blazor WebAssembly needs 'wasm-unsafe-eval'; MudBlazor sets inline styles.
    private const string Csp =
        "default-src 'self'; " +
        "script-src 'self' 'wasm-unsafe-eval'; " +
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
        "font-src 'self' https://fonts.gstatic.com; " +
        "img-src 'self' data:; " +
        "connect-src 'self'; " +
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers.XFrameOptions = "DENY";
        headers["Referrer-Policy"] = "no-referrer";
        headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()";
        headers["Cross-Origin-Opener-Policy"] = "same-origin";
        headers.ContentSecurityPolicy = Csp;
        return next(context);
    }
}
