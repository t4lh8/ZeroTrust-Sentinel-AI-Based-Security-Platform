using System.Threading.RateLimiting;
using Sentinel.Api.Data;
using Sentinel.Api.Demo;
using Sentinel.Api.Detection;
using Sentinel.Api.Endpoints;
using Sentinel.Api.Monitoring;
using Sentinel.Api.Security;

var builder = WebApplication.CreateBuilder(args);

// Settings are read when services are first resolved, not here, so every configuration source
// (appsettings, environment variables, test hosts) is taken into account.
static T Settings<T>(IServiceProvider sp, string section) where T : new() =>
    sp.GetRequiredService<IConfiguration>().GetSection(section).Get<T>() ?? new T();

builder.Services.AddSentinelDatabase();
builder.Services.AddSentinelAuth();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuditLogger>();
builder.Services.AddSignalR();
builder.Services.AddProblemDetails();

// Detection pipeline: queue -> processor (rules + Isolation Forest) -> database + SignalR.
builder.Services.AddSingleton(sp => Settings<DetectionOptions>(sp, DetectionOptions.Section));
builder.Services.AddSingleton(sp => Settings<DemoOptions>(sp, DemoOptions.Section));
builder.Services.AddSingleton<AnomalyModels>();
builder.Services.AddSingleton<ThreatDetector>();
builder.Services.AddSingleton<EventQueue>();
builder.Services.AddSingleton<ModelTrainer>();
builder.Services.AddHostedService<EventProcessor>();
builder.Services.AddHostedService(sp => sp.GetRequiredService<ModelTrainer>());
builder.Services.AddHostedService<TrafficSimulator>();

builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    static int Limit(HttpContext ctx, string key, int fallback) =>
        ctx.RequestServices.GetRequiredService<IConfiguration>().GetValue(key, fallback);

    // Login: a few attempts per minute per IP, which makes online password guessing impractical.
    o.AddPolicy(AuthEndpoints.LoginRateLimitPolicy, ctx => RateLimitPartition.GetFixedWindowLimiter(ctx.ClientIp(),
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Limit(ctx, "RateLimit:LoginPerMinute", 5),
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        }));

    // Everything under /api: a token bucket per IP absorbs normal bursts but stops floods and scrapers.
    o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
        ctx.Request.Path.StartsWithSegments("/api")
            ? RateLimitPartition.GetTokenBucketLimiter(ctx.ClientIp(), _ => new TokenBucketRateLimiterOptions
            {
                TokenLimit = Limit(ctx, "RateLimit:ApiPerMinute", 120),
                TokensPerPeriod = Limit(ctx, "RateLimit:ApiPerMinute", 120),
                ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                QueueLimit = 0,
            })
            : RateLimitPartition.GetNoLimiter("unlimited"));
});

var app = builder.Build();

await app.InitializeDatabaseAsync();

app.UseExceptionHandler();
app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseMiddleware<RequestMonitoringMiddleware>();

// A request that matched no endpoint (e.g. a scanner probing /backup.zip) is answered with 404 here.
// Otherwise the fallback auth policy would turn it into a 401.
app.Use((context, next) =>
{
    if (context.GetEndpoint() is not null) return next(context);
    context.Response.StatusCode = StatusCodes.Status404NotFound;
    return Task.CompletedTask;
});

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/health", () => Results.Ok(new { status = "healthy" })).AllowAnonymous();
app.MapAuthEndpoints();
app.MapDashboardEndpoints();
app.MapHoneypotEndpoints(app.Services.GetRequiredService<DetectionOptions>());
app.MapHub<AlertHub>("/hubs/alerts");

// The Blazor WebAssembly dashboard: its files are public, the data behind it is not.
app.MapStaticAssets().AllowAnonymous();
app.MapFallbackToFile("index.html").AllowAnonymous();

app.Run();

public partial class Program;
