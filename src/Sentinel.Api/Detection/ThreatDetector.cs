using Sentinel.Api.Data;
using Sentinel.Shared;

namespace Sentinel.Api.Detection;

/// <summary>
/// Analyses each security event with two layers:
///   1. Deterministic rules for well-known attacks (brute force, honeypots, scanners...). Precise and explainable.
///   2. Isolation Forest models that flag behaviour unlike anything seen before. Catches what rules miss.
/// </summary>
public sealed class ThreatDetector(DetectionOptions options, AnomalyModels models)
{
    private readonly ActivityTracker _tracker = new();
    private readonly Dictionary<string, DateTime> _cooldowns = new();
    private readonly HashSet<string> _honeytokens = new(options.Honeytokens, StringComparer.OrdinalIgnoreCase);

    public static bool IsLogin(EventType type) => type is EventType.LoginSuccess or EventType.LoginFailure;

    /// <summary>Seed a user's baseline (known IPs, usual hours) from stored history after a restart.</summary>
    public void LearnBaseline(string user, string ip, DateTime time) => _tracker.LearnSuccessfulLogin(user, ip, time);

    /// <summary>Scores the event (sets Features and AnomalyScore on it) and returns any alerts it triggers.</summary>
    public List<Alert> Analyze(SecurityEvent ev)
    {
        var now = ev.TimestampUtc;
        var ip = ev.SourceIp;
        _tracker.Record(now, ev.Type, ip, ev.Username, ev.Path, ev.StatusCode);

        var model = IsLogin(ev.Type) ? models.Login : models.Traffic;
        var features = IsLogin(ev.Type) ? _tracker.LoginFeatures(now, ip, ev.Username) : _tracker.TrafficFeatures(now, ip);

        // Honeypot hits are attacks by definition; keep them out of the "normal traffic" training data.
        if (ev.Type != EventType.HoneypotHit)
        {
            ev.Features = AnomalyModel.Serialize(features);
            ev.AnomalyScore = model.Score(features) is { } s ? Math.Round(s, 3) : null;
        }

        var alerts = new List<Alert>();
        ApplyRules(ev, features, alerts);

        // The AI layer only speaks up when no rule already explained the event.
        if (alerts.Count == 0 && ev.AnomalyScore >= model.Threshold)
            AddAiAlert(ev, model, features, alerts);

        if (ev.Type == EventType.LoginSuccess && ev.Username is not null)
            _tracker.LearnSuccessfulLogin(ev.Username, ip, now);

        return alerts;
    }

    private void ApplyRules(SecurityEvent ev, double[] f, List<Alert> alerts)
    {
        var ip = ev.SourceIp;
        var now = ev.TimestampUtc;

        switch (ev.Type)
        {
            case EventType.HoneypotHit:
                Raise(alerts, ev, "Honeypot", Severity.Critical, 95, TimeSpan.FromMinutes(5),
                    $"Honeypot triggered: {ev.Path}",
                    $"{ip} requested the trap URL {ev.Method} {ev.Path}. No legitimate user or client ever calls this path, " +
                    "so the source is almost certainly an automated scanner or an attacker doing reconnaissance.");
                break;

            case EventType.LoginFailure or EventType.LoginSuccess when ev.Username is not null && _honeytokens.Contains(ev.Username):
                Raise(alerts, ev, "Honeytoken", Severity.Critical, 99, TimeSpan.FromMinutes(1),
                    $"Honeytoken credential used: {ev.Username}",
                    $"{ip} tried to log in as '{ev.Username}'. This account does not exist: its credentials were only ever " +
                    "published inside a honeypot response (fake .env file). Whoever uses them harvested data from a trap.");
                break;

            case EventType.LoginFailure:
                if (f[1] >= options.CredentialStuffingThreshold)
                    Raise(alerts, ev, "Credential stuffing", Severity.High, 85, TimeSpan.FromMinutes(10),
                        $"Credential stuffing from {ip}",
                        $"{f[1]} different usernames were tried from {ip} in 10 minutes. This pattern matches leaked " +
                        "username/password lists being replayed against the login.");
                else if (f[0] >= options.BruteForceThreshold)
                    Raise(alerts, ev, "Brute force", Severity.High, 80, TimeSpan.FromMinutes(10),
                        $"Brute-force attack on '{ev.Username}'",
                        $"{f[0]} failed logins from {ip} in 10 minutes. The login rate limiter slows this down, " +
                        "but the source should be blocked at the firewall/WAF.");

                if (f[2] >= options.TargetedAccountThreshold)
                    Raise(alerts, ev, "Targeted account", Severity.High, 80, TimeSpan.FromMinutes(10),
                        $"Account '{ev.Username}' under attack", $"{f[2]} failed logins for '{ev.Username}' in 10 minutes, " +
                        "possibly from several IPs (distributed brute force). Consider forcing MFA or a password reset.",
                        key: ev.Username);
                break;

            case EventType.AccessDenied:
                var denied = _tracker.CountForIp(ip, now, TimeSpan.FromMinutes(10), (t, _) => t == EventType.AccessDenied);
                if (denied >= options.PrivilegeProbingThreshold)
                    Raise(alerts, ev, "Privilege probing", Severity.Medium, 60, TimeSpan.FromMinutes(10),
                        $"Privilege probing by {ev.Username ?? ip}",
                        $"{denied} requests to endpoints outside the caller's role were denied in 10 minutes " +
                        $"(latest: {ev.Method} {ev.Path}). A compromised low-privilege account may be exploring the API.");
                break;

            case EventType.RateLimited:
                var limited = _tracker.CountForIp(ip, now, TimeSpan.FromMinutes(1), (t, _) => t == EventType.RateLimited);
                if (limited >= options.FloodRateLimitedThreshold)
                    Raise(alerts, ev, "Request flood", Severity.Medium, 65, TimeSpan.FromMinutes(10),
                        $"Request flood from {ip}",
                        $"{limited} requests from {ip} were rejected by the rate limiter in one minute. " +
                        "Possible scraping, denial-of-service attempt or a misbehaving client.");
                break;

            case EventType.Request:
                if (f[3] >= options.ScannerNotFoundThreshold)
                    Raise(alerts, ev, "Web scanner", Severity.Medium, 60, TimeSpan.FromMinutes(10),
                        $"Directory scanning from {ip}",
                        $"{f[3]} requests from {ip} hit non-existent paths in one minute (latest: {ev.Path}). " +
                        "Typical for tools like dirbuster, gobuster or nikto mapping the attack surface.");
                break;
        }
    }

    private void AddAiAlert(SecurityEvent ev, AnomalyModel model, double[] features, List<Alert> alerts)
    {
        var score = ev.AnomalyScore!.Value;
        var reasons = model.Explain(features);
        var why = reasons.Count > 0 ? " Most unusual: " + string.Join("; ", reasons) + "." : "";

        var (severity, title) = ev.Type switch
        {
            EventType.LoginSuccess => (Severity.High, $"Anomalous successful login for '{ev.Username}'"),
            EventType.LoginFailure => (Severity.Medium, $"Anomalous login attempt for '{ev.Username}'"),
            _ => (Severity.Medium, $"Anomalous traffic pattern from {ev.SourceIp}"),
        };

        var context = ev.Type == EventType.LoginSuccess
            ? " A successful login that looks this different from the user's history may indicate account takeover."
            : "";

        // Cooldown per event type: alerts on failed attempts must not silence the more serious
        // alert when the attacker finally logs in successfully.
        Raise(alerts, ev, "AI anomaly", severity, Math.Round(score * 100, 1), TimeSpan.FromMinutes(10), title,
            $"The {model.Name.ToLowerInvariant()} model (Isolation Forest) scored this event {score:0.00} " +
            $"(threshold {model.Threshold:0.00}).{why}{context}",
            key: $"{ev.SourceIp}|{ev.Type}");
    }

    private void Raise(List<Alert> alerts, SecurityEvent ev, string category, Severity severity, double risk,
        TimeSpan cooldown, string title, string description, string? key = null)
    {
        // One alert per category and source per cooldown window, so an attack is one alert, not hundreds.
        var cooldownKey = $"{category}|{key ?? ev.SourceIp}";
        if (_cooldowns.TryGetValue(cooldownKey, out var last) && ev.TimestampUtc - last < cooldown) return;
        _cooldowns[cooldownKey] = ev.TimestampUtc;

        if (_cooldowns.Count > 10_000)
            foreach (var (k, t) in _cooldowns.ToList())
                if (ev.TimestampUtc - t > TimeSpan.FromHours(1)) _cooldowns.Remove(k);

        alerts.Add(new Alert
        {
            CreatedAtUtc = ev.TimestampUtc,
            Severity = severity,
            Category = category,
            Title = title,
            Description = description,
            SourceIp = ev.SourceIp,
            Username = ev.Username,
            RiskScore = risk,
        });
    }
}
