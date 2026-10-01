using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Sentinel.Shared;

namespace Sentinel.Tests;

public sealed class SentinelFactory : WebApplicationFactory<Program>
{
    public const string AdminPassword = "Admin!Test-Password1";
    public const string AnalystPassword = "Analyst!Test-Password1";
    public const string ViewerPassword = "Viewer!Test-Password1";

    private readonly string _dbPath = Path.Combine(Path.GetTempPath(), $"sentinel-test-{Guid.NewGuid():N}.db");

    public int LoginLimit { get; init; } = 1000;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Database:Provider", "Sqlite");
        builder.UseSetting("ConnectionStrings:Sentinel", $"Data Source={_dbPath}");
        builder.UseSetting("Jwt:Key", "test-signing-key-that-is-long-enough-0123456789");
        builder.UseSetting("Seed:AdminPassword", AdminPassword);
        builder.UseSetting("Seed:AnalystPassword", AnalystPassword);
        builder.UseSetting("Seed:ViewerPassword", ViewerPassword);
        builder.UseSetting("Demo:Enabled", "false");
        builder.UseSetting("RateLimit:LoginPerMinute", LoginLimit.ToString());
        builder.UseSetting("RateLimit:ApiPerMinute", "10000");
        builder.ConfigureServices(services => services.AddTransient<IStartupFilter, TestClientIpFilter>());
    }

    /// <summary>A client whose requests appear to come from the given IP, so tests don't share detection cooldowns.</summary>
    public HttpClient CreateClient(string ip)
    {
        var client = CreateClient();
        client.DefaultRequestHeaders.Add(TestClientIpFilter.Header, ip);
        return client;
    }

    public async Task<HttpClient> ClientForAsync(string username, string password)
    {
        var client = CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest(username, password));
        response.EnsureSuccessStatusCode();
        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", login!.Token);
        return client;
    }

    private sealed class TestClientIpFilter : IStartupFilter
    {
        public const string Header = "X-Test-Client-Ip";

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                if (IPAddress.TryParse(context.Request.Headers[Header], out var ip)) context.Connection.RemoteIpAddress = ip;
                return nextMiddleware(context);
            });
            next(app);
        };
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { File.Delete(_dbPath); } catch (IOException) { }
    }
}

public class ApiTests(SentinelFactory factory) : IClassFixture<SentinelFactory>
{
    /// <summary>Events are analysed asynchronously, so poll until the expected alert shows up.</summary>
    private static async Task<AlertDto> WaitForAlertAsync(HttpClient client, Func<AlertDto, bool> match)
    {
        for (var i = 0; i < 50; i++)
        {
            var alerts = await client.GetFromJsonAsync<List<AlertDto>>("/api/alerts?take=500");
            var alert = alerts!.FirstOrDefault(match);
            if (alert is not null) return alert;
            await Task.Delay(100);
        }
        throw new TimeoutException("Expected alert was not raised.");
    }

    [Fact]
    public async Task Api_requires_authentication()
    {
        var response = await factory.CreateClient().GetAsync("/api/overview");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Wrong_password_is_rejected_and_audited()
    {
        var client = factory.CreateClient();
        var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("admin", "wrong-password"));
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var admin = await factory.ClientForAsync("admin", SentinelFactory.AdminPassword);
        var audit = await admin.GetFromJsonAsync<List<AuditLogDto>>("/api/audit");
        Assert.Contains(audit!, a => a.Action == "auth.login" && a.Target == "admin" && !a.Success);
    }

    [Fact]
    public async Task Unknown_user_gets_the_same_error_as_wrong_password()
    {
        var client = factory.CreateClient();
        var unknown = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("no-such-user", "whatever-password"));
        var wrong = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("admin", "whatever-password"));

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(await wrong.Content.ReadAsStringAsync(), await unknown.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task Login_returns_a_token_with_the_users_role()
    {
        var client = await factory.ClientForAsync("analyst", SentinelFactory.AnalystPassword);
        var me = await client.GetFromJsonAsync<CurrentUserDto>("/api/auth/me");
        Assert.Equal(new CurrentUserDto("analyst", Roles.Analyst), me);
    }

    [Fact]
    public async Task Viewer_cannot_use_admin_endpoints()
    {
        var viewer = await factory.ClientForAsync("viewer", SentinelFactory.ViewerPassword);
        Assert.Equal(HttpStatusCode.OK, (await viewer.GetAsync("/api/overview")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/audit")).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.GetAsync("/api/users")).StatusCode);
    }

    [Fact]
    public async Task Honeypot_serves_bait_and_raises_a_critical_alert()
    {
        var response = await factory.CreateClient("203.0.113.10").GetAsync("/.env");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("ADMIN_PASSWORD", await response.Content.ReadAsStringAsync());

        var admin = await factory.ClientForAsync("admin", SentinelFactory.AdminPassword);
        var alert = await WaitForAlertAsync(admin, a => a.Category == "Honeypot");
        Assert.Equal(Severity.Critical, alert.Severity);
    }

    [Fact]
    public async Task Using_a_honeytoken_raises_a_critical_alert()
    {
        await factory.CreateClient("203.0.113.11").PostAsJsonAsync("/api/auth/login", new LoginRequest("backup_admin", "Spring2024!backup"));

        var admin = await factory.ClientForAsync("admin", SentinelFactory.AdminPassword);
        var alert = await WaitForAlertAsync(admin, a => a.Category == "Honeytoken");
        Assert.Equal("backup_admin", alert.Username);
    }

    [Fact]
    public async Task Only_analysts_and_admins_can_handle_alerts()
    {
        await factory.CreateClient("203.0.113.12").GetAsync("/wp-login.php");
        var analyst = await factory.ClientForAsync("analyst", SentinelFactory.AnalystPassword);
        var alert = await WaitForAlertAsync(analyst, a => a.Title.Contains("/wp-login.php"));

        var viewer = await factory.ClientForAsync("viewer", SentinelFactory.ViewerPassword);
        Assert.Equal(HttpStatusCode.Forbidden, (await viewer.PostAsync($"/api/alerts/{alert.Id}/acknowledge", null)).StatusCode);

        var response = await analyst.PostAsync($"/api/alerts/{alert.Id}/acknowledge", null);
        var updated = await response.Content.ReadFromJsonAsync<AlertDto>();
        Assert.Equal(AlertStatus.Acknowledged, updated!.Status);
        Assert.Equal("analyst", updated.HandledBy);
    }

    [Fact]
    public async Task Deactivating_a_user_revokes_their_existing_token()
    {
        var admin = await factory.ClientForAsync("admin", SentinelFactory.AdminPassword);
        var created = await admin.PostAsJsonAsync("/api/users", new CreateUserRequest("temp.user", "Temporary!Pass123", Roles.Viewer));
        var user = await created.Content.ReadFromJsonAsync<UserDto>();

        var temp = await factory.ClientForAsync("temp.user", "Temporary!Pass123");
        Assert.Equal(HttpStatusCode.OK, (await temp.GetAsync("/api/overview")).StatusCode);

        await admin.PostAsync($"/api/users/{user!.Id}/deactivate", null);

        // Same token, still unexpired and correctly signed, is now refused.
        Assert.Equal(HttpStatusCode.Unauthorized, (await temp.GetAsync("/api/overview")).StatusCode);
    }

    [Fact]
    public async Task Weak_passwords_are_rejected()
    {
        var admin = await factory.ClientForAsync("admin", SentinelFactory.AdminPassword);
        var response = await admin.PostAsJsonAsync("/api/users", new CreateUserRequest("weak.user", "short", Roles.Viewer));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Responses_carry_security_headers()
    {
        var response = await factory.CreateClient().GetAsync("/health");
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("DENY", response.Headers.GetValues("X-Frame-Options").Single());
        Assert.Contains("frame-ancestors 'none'", response.Headers.GetValues("Content-Security-Policy").Single());
    }

    [Fact]
    public async Task Unknown_files_return_404_not_401()
    {
        var response = await factory.CreateClient().GetAsync("/backup.zip");
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}

public class RateLimitTests
{
    [Fact]
    public async Task Login_is_rate_limited_per_ip()
    {
        using var factory = new SentinelFactory { LoginLimit = 3 };
        var client = factory.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 5; i++)
            statuses.Add((await client.PostAsJsonAsync("/api/auth/login", new LoginRequest("admin", "guess-" + i))).StatusCode);

        Assert.Equal([HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized, HttpStatusCode.Unauthorized,
                      HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests], statuses);
    }
}
