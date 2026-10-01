using Sentinel.Api.Data;
using Sentinel.Api.Detection;
using Sentinel.Shared;

namespace Sentinel.Tests;

public class ThreatDetectorTests
{
    private static readonly DateTime T0 = new(2026, 3, 1, 12, 0, 0, DateTimeKind.Utc);
    private readonly DetectionOptions _options = new();
    private readonly ThreatDetector _detector;

    public ThreatDetectorTests() => _detector = new ThreatDetector(_options, new AnomalyModels(_options));

    private static SecurityEvent Event(EventType type, string ip, string? user = null, int seconds = 0, string path = "/api/auth/login", int status = 401) => new()
    {
        TimestampUtc = T0.AddSeconds(seconds),
        Type = type,
        SourceIp = ip,
        Username = user,
        Path = path,
        StatusCode = status,
    };

    [Fact]
    public void Brute_force_raises_one_alert_at_threshold()
    {
        var alerts = Enumerable.Range(0, 10)
            .SelectMany(i => _detector.Analyze(Event(EventType.LoginFailure, "203.0.113.5", "admin", i)))
            .ToList();

        // Cooldown: one brute-force alert per attack, not one per attempt.
        var alert = Assert.Single(alerts, a => a.Category == "Brute force");
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Equal("203.0.113.5", alert.SourceIp);
    }

    [Fact]
    public void Failures_spread_over_time_do_not_trigger_brute_force()
    {
        var alerts = Enumerable.Range(0, 6)
            .SelectMany(i => _detector.Analyze(Event(EventType.LoginFailure, "192.0.2.1", "alice", i * 300)))
            .ToList();
        Assert.Empty(alerts);
    }

    [Fact]
    public void Many_usernames_from_one_ip_is_credential_stuffing()
    {
        var users = new[] { "admin", "root", "test", "oracle", "guest" };
        var alerts = users.SelectMany((u, i) => _detector.Analyze(Event(EventType.LoginFailure, "198.51.100.9", u, i))).ToList();
        Assert.Contains(alerts, a => a.Category == "Credential stuffing");
    }

    [Fact]
    public void Honeypot_hit_is_critical()
    {
        var alerts = _detector.Analyze(Event(EventType.HoneypotHit, "203.0.113.77", path: "/.env", status: 200));
        var alert = Assert.Single(alerts);
        Assert.Equal(Severity.Critical, alert.Severity);
        Assert.Equal("Honeypot", alert.Category);
    }

    [Fact]
    public void Honeytoken_login_is_critical_even_on_first_attempt()
    {
        var alerts = _detector.Analyze(Event(EventType.LoginFailure, "203.0.113.8", "backup_admin"));
        var alert = Assert.Single(alerts);
        Assert.Equal("Honeytoken", alert.Category);
        Assert.Equal(Severity.Critical, alert.Severity);
    }

    [Fact]
    public void Repeated_access_denied_is_privilege_probing()
    {
        var alerts = Enumerable.Range(0, 3)
            .SelectMany(i => _detector.Analyze(Event(EventType.AccessDenied, "192.0.2.40", "viewer", i * 10, "/api/users", 403)))
            .ToList();
        Assert.Contains(alerts, a => a.Category == "Privilege probing");
    }

    [Fact]
    public void Many_404s_is_a_web_scanner()
    {
        var alerts = Enumerable.Range(0, 20)
            .SelectMany(i => _detector.Analyze(Event(EventType.Request, "198.51.100.3", null, i, $"/backup{i}.zip", 404)))
            .ToList();
        Assert.Contains(alerts, a => a.Category == "Web scanner");
    }

    [Fact]
    public void Untrained_models_leave_score_empty_but_rules_still_work()
    {
        var ev = Event(EventType.LoginSuccess, "192.0.2.10", "alice", status: 200);
        var alerts = _detector.Analyze(ev);
        Assert.Null(ev.AnomalyScore);
        Assert.NotNull(ev.Features);
        Assert.Empty(alerts);
    }

    [Fact]
    public void Trained_model_flags_account_takeover_login()
    {
        // Baseline: alice always logs in around 09:00 from her office IP.
        var models = new AnomalyModels(_options);
        var detector = new ThreatDetector(_options, models);
        var history = new List<double[]>();
        for (var day = 0; day < 30; day++)
        {
            var ev = Event(EventType.LoginSuccess, "192.0.2.10", "alice", status: 200);
            ev.TimestampUtc = new DateTime(2026, 2, 1, 9, 0, 0, DateTimeKind.Utc).AddDays(day).AddMinutes(day % 40);
            detector.Analyze(ev);
            history.Add(AnomalyModel.Deserialize(ev.Features!));
        }
        Assert.True(models.Login.Train(history.Concat(history).ToList(), seed: 3));

        // Then: a few failures and a success at 03:00 from an unknown IP.
        var attackTime = new DateTime(2026, 3, 5, 3, 0, 0, DateTimeKind.Utc);
        for (var i = 0; i < 3; i++)
        {
            var fail = Event(EventType.LoginFailure, "203.0.113.200", "alice");
            fail.TimestampUtc = attackTime.AddSeconds(i * 20);
            detector.Analyze(fail);
        }
        var success = Event(EventType.LoginSuccess, "203.0.113.200", "alice", status: 200);
        success.TimestampUtc = attackTime.AddMinutes(2);
        var alerts = detector.Analyze(success);

        var alert = Assert.Single(alerts);
        Assert.Equal("AI anomaly", alert.Category);
        Assert.Equal(Severity.High, alert.Severity);
        Assert.Contains("new IP for user", alert.Description);
    }
}
