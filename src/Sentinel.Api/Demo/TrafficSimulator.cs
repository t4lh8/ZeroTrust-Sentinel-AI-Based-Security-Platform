using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Data;
using Sentinel.Api.Monitoring;
using Sentinel.Shared;

namespace Sentinel.Api.Demo;

public sealed class DemoOptions
{
    public const string Section = "Demo";

    public bool Enabled { get; set; }
    public int BackfillDays { get; set; } = 3;

    /// <summary>Average seconds between simulated attack scenarios.</summary>
    public int AttackIntervalSeconds { get; set; } = 25;
}

/// <summary>
/// Demo mode: generates realistic traffic so the dashboard has something to show without real users.
/// It first backfills a few days of normal history (so the anomaly models can train), then streams
/// live normal activity mixed with attack scenarios. All IPs come from the RFC 5737 documentation
/// ranges, so no real address ever appears. Events go through exactly the same detection pipeline
/// as real HTTP traffic.
/// </summary>
public sealed class TrafficSimulator(
    EventQueue queue,
    ModelTrainer trainer,
    DemoOptions options,
    IServiceScopeFactory scopes,
    ILogger<TrafficSimulator> logger) : BackgroundService
{
    private sealed record Employee(string Name, int UsualHour, string[] Ips, string Role);

    // A distributed team: usual working hours are spread over the clock (different time zones / shifts).
    private static readonly Employee[] Team =
    [
        new("ingrid.solberg", 8, ["192.0.2.11"], Roles.Admin),
        new("jonas.lie", 9, ["192.0.2.12", "192.0.2.112"], Roles.Analyst),
        new("emma.hansen", 10, ["192.0.2.13"], Roles.Analyst),
        new("ali.yilmaz", 12, ["192.0.2.14"], Roles.Viewer),
        new("sara.nilsen", 14, ["192.0.2.15", "192.0.2.115"], Roles.Viewer),
        new("lucas.berg", 16, ["192.0.2.16"], Roles.Analyst),
        new("nora.dahl", 18, ["192.0.2.17"], Roles.Viewer),
        new("mehmet.kaya", 20, ["192.0.2.18"], Roles.Viewer),
        new("olivia.strand", 22, ["192.0.2.19"], Roles.Analyst),
        new("kenji.sato", 0, ["192.0.2.20"], Roles.Viewer),
        new("priya.sharma", 3, ["192.0.2.21"], Roles.Analyst),
        new("diego.alvarez", 5, ["192.0.2.22"], Roles.Viewer),
    ];

    private static readonly string[] ApiPaths =
        ["/api/overview", "/api/alerts", "/api/events", "/api/auth/me", "/api/alerts?status=Open", "/api/events?type=LoginFailure"];

    private static readonly string[] ScannerPaths =
        ["/backup.zip", "/db.sql", "/.htaccess", "/old/", "/test.php", "/config.bak", "/admin/login.asp", "/shell.php",
         "/uploads/", "/.DS_Store", "/backup.tar.gz", "/install.php", "/debug.log", "/cgi-bin/test.cgi", "/console",
         "/api/swagger.json", "/web.config", "/robots.txt.bak", "/dump.sql", "/.svn/entries", "/xmlrpc.php"];

    private static readonly string[] CommonUsernames =
        ["admin", "root", "administrator", "test", "user", "support", "guest", "info", "oracle", "postgres"];

    private const string Browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36";

    // Sessions and attack scenarios run concurrently, so use the thread-safe shared instance.
    private static Random _random => Random.Shared;

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (!options.Enabled) return;

        await BackfillHistoryAsync(ct);

        var nextAttack = DateTime.UtcNow.AddSeconds(8);
        while (!ct.IsCancellationRequested)
        {
            StartSessionIfNeeded(ct);

            if (DateTime.UtcNow >= nextAttack)
            {
                _ = RunAttackScenarioAsync(ct); // runs alongside normal traffic
                nextAttack = DateTime.UtcNow.AddSeconds(options.AttackIntervalSeconds * (0.6 + _random.NextDouble() * 0.8));
            }
            await Task.Delay(TimeSpan.FromSeconds(1), ct);
        }
    }

    // ---------- Normal user sessions ----------

    // The same session generator feeds both the history backfill and the live stream. If live "normal"
    // traffic looked different from the training data, the models would flag ordinary users.
    private sealed record Step(TimeSpan Offset, EventType Type, string Method, string Path, int Status);

    private List<Step> NewSession()
    {
        var steps = new List<Step>();
        if (_random.NextDouble() < 0.08) // the occasional typo
            steps.Add(new Step(TimeSpan.FromSeconds(-15), EventType.LoginFailure, "POST", "/api/auth/login", 401));
        steps.Add(new Step(TimeSpan.Zero, EventType.LoginSuccess, "POST", "/api/auth/login", 200));

        var offset = TimeSpan.Zero;
        var requests = 6 + _random.Next(20);
        var reloginAt = _random.NextDouble() < 0.3 ? _random.Next(3, requests) : -1;
        for (var r = 0; r < requests; r++)
        {
            offset += TimeSpan.FromSeconds(4 + _random.Next(14)); // roughly the dashboard's polling rhythm
            // Logging in again mid-session (expired token, new tab) is normal and must not look like an attack.
            if (r == reloginAt) steps.Add(new Step(offset - TimeSpan.FromSeconds(1), EventType.LoginSuccess, "POST", "/api/auth/login", 200));
            steps.Add(new Step(offset, EventType.Request, "GET", Pick(ApiPaths), 200));
        }
        return steps;
    }

    private async Task BackfillHistoryAsync(CancellationToken ct)
    {
        using (var scope = scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
            if (await db.Events.AnyAsync(ct))
            {
                await trainer.TrainNowAsync(ct);
                return;
            }
        }

        logger.LogInformation("Demo mode: backfilling {Days} days of normal activity for model training", options.BackfillDays);
        var events = new List<SecurityEvent>();
        var start = DateTime.UtcNow.Date.AddDays(-options.BackfillDays);

        foreach (var employee in Team)
        {
            for (var day = 0; day < options.BackfillDays; day++)
            {
                var sessions = 3 + _random.Next(4);
                for (var s = 0; s < sessions; s++)
                {
                    var hour = employee.UsualHour + Gaussian() * 1.2;
                    var time = start.AddDays(day).AddHours((hour + 24) % 24);
                    if (time > DateTime.UtcNow.AddMinutes(-30)) continue;

                    var ip = Pick(employee.Ips);
                    events.AddRange(NewSession().Select(step =>
                        Event(time + step.Offset, step.Type, ip, employee.Name, step.Method, step.Path, step.Status)));
                }
            }
        }

        foreach (var ev in events.OrderBy(e => e.TimestampUtc)) await queue.EnqueueAsync(ev, ct);
        while (queue.Pending > 0) await Task.Delay(200, ct);

        await trainer.TrainNowAsync(ct);
        logger.LogInformation("Demo mode: backfilled {Count} events, starting live simulation", events.Count);
    }

    private readonly HashSet<string> _inSession = [];
    private readonly Dictionary<string, DateTime> _lastSessionEnd = [];

    private void StartSessionIfNeeded(CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var hour = now.Hour + now.Minute / 60.0;
        Employee employee;
        lock (_inSession)
        {
            var available = Team.Where(e => CircularDistance(e.UsualHour, hour) <= 2 && !_inSession.Contains(e.Name) &&
                    now - _lastSessionEnd.GetValueOrDefault(e.Name) > TimeSpan.FromMinutes(10)).ToArray();
            if (available.Length == 0 || _inSession.Count >= 3 || _random.NextDouble() > 0.15) return;
            employee = Pick(available);
            _inSession.Add(employee.Name);
        }
        _ = RunSessionAsync(employee, ct);
    }

    private async Task RunSessionAsync(Employee employee, CancellationToken ct)
    {
        try
        {
            var ip = Pick(employee.Ips);
            var previous = TimeSpan.Zero;
            foreach (var step in NewSession().OrderBy(s => s.Offset))
            {
                if (step.Offset > previous) await Task.Delay(step.Offset - previous, ct);
                previous = step.Offset;
                queue.TryEnqueue(Event(DateTime.UtcNow, step.Type, ip, employee.Name, step.Method, step.Path, step.Status));
            }
        }
        catch (OperationCanceledException) { }
        finally
        {
            lock (_inSession)
            {
                _inSession.Remove(employee.Name);
                _lastSessionEnd[employee.Name] = DateTime.UtcNow;
            }
        }
    }

    // ---------- Attack scenarios ----------

    private async Task RunAttackScenarioAsync(CancellationToken ct)
    {
        try
        {
            var scenario = _random.Next(9);
            var attacker = AttackerIp();
            switch (scenario)
            {
                case 0 or 1: // brute force against a likely admin account
                    var target = _random.NextDouble() < 0.5 ? "admin" : Pick(Team).Name;
                    for (var i = 0; i < 6 + _random.Next(8); i++)
                        await Emit(EventType.LoginFailure, attacker, target, "POST", "/api/auth/login", 401, ct, delayMs: 300);
                    break;

                case 2: // credential stuffing with a leaked list
                    foreach (var user in CommonUsernames.OrderBy(_ => _random.Next()).Take(5 + _random.Next(4)))
                        await Emit(EventType.LoginFailure, attacker, user, "POST", "/api/auth/login", 401, ct, delayMs: 500);
                    break;

                case 3: // reconnaissance hitting honeypots, then trying the harvested honeytoken
                    foreach (var trap in new[] { "/.env", "/.git/config", "/wp-login.php" }.Take(1 + _random.Next(3)))
                        await Emit(EventType.HoneypotHit, attacker, null, "GET", trap, 200, ct, delayMs: 700);
                    if (_random.NextDouble() < 0.6)
                        await Emit(EventType.LoginFailure, attacker, "backup_admin", "POST", "/api/auth/login", 401, ct, delayMs: 2000);
                    break;

                case 4: // directory brute forcing
                    foreach (var path in ScannerPaths.OrderBy(_ => _random.Next()))
                        await Emit(EventType.Request, attacker, null, "GET", path, 404, ct, delayMs: 120);
                    break;

                case 5: // compromised viewer account exploring admin endpoints
                    var viewer = Pick(Team.Where(e => e.Role == Roles.Viewer).ToArray());
                    foreach (var path in new[] { "/api/users", "/api/audit", "/api/users", "/api/alerts/3f2a/resolve", "/api/audit?take=1000" })
                        await Emit(EventType.AccessDenied, Pick(viewer.Ips), viewer.Name, path.Contains("resolve") ? "POST" : "GET", path, 403, ct, delayMs: 900);
                    break;

                case 6: // request flood hitting the rate limiter
                    for (var i = 0; i < 25; i++)
                        await Emit(EventType.RateLimited, attacker, null, "GET", "/api/overview", 429, ct, delayMs: 60);
                    break;

                default: // account takeover: off-hours login from a never-seen IP after a few failures
                    var now = DateTime.UtcNow.Hour;
                    var victim = Pick(Team.Where(e => CircularDistance(e.UsualHour, now) >= 7).ToArray());
                    for (var i = 0; i < 1 + _random.Next(3); i++)
                        await Emit(EventType.LoginFailure, attacker, victim.Name, "POST", "/api/auth/login", 401, ct, delayMs: 1500);
                    await Emit(EventType.LoginSuccess, attacker, victim.Name, "POST", "/api/auth/login", 200, ct, delayMs: 1500);
                    break;
            }
        }
        catch (OperationCanceledException) { }
    }

    // ---------- Helpers ----------

    private async Task Emit(EventType type, string ip, string? user, string method, string path, int status, CancellationToken ct, int delayMs = 0)
    {
        if (delayMs > 0) await Task.Delay(delayMs / 2 + _random.Next(delayMs), ct);
        queue.TryEnqueue(Event(DateTime.UtcNow, type, ip, user, method, path, status));
    }

    private SecurityEvent Event(DateTime time, EventType type, string ip, string? user, string method, string path, int status) => new()
    {
        TimestampUtc = time,
        Type = type,
        SourceIp = ip,
        Username = user,
        Method = method,
        Path = path,
        StatusCode = status,
        UserAgent = ip.StartsWith("192.0.2.") ? Browser : Pick(AttackerAgents),
    };

    private static readonly string[] AttackerAgents =
        ["python-requests/2.32", "curl/8.5.0", "Mozilla/5.0 zgrab/0.x", "gobuster/3.6", "Nikto/2.5.0", "Hydra"];

    private static string AttackerIp() =>
        (_random.Next(2) == 0 ? "203.0.113." : "198.51.100.") + _random.Next(1, 255);

    private static T Pick<T>(T[] items) => items[_random.Next(items.Length)];

    private static double Gaussian() =>
        Math.Sqrt(-2 * Math.Log(1 - _random.NextDouble())) * Math.Cos(2 * Math.PI * _random.NextDouble());

    private static double CircularDistance(double a, double b)
    {
        var d = Math.Abs(a - b) % 24;
        return Math.Min(d, 24 - d);
    }
}
