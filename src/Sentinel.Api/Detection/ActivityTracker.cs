using Sentinel.Shared;

namespace Sentinel.Api.Detection;

/// <summary>
/// Sliding windows of recent activity per IP and per user, plus each user's login baseline.
/// Time is taken from the events themselves, so replayed history behaves exactly like live traffic.
/// Only the event processor touches this class, so it is deliberately not thread-safe.
/// </summary>
public sealed class ActivityTracker
{
    private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan ShortWindow = TimeSpan.FromMinutes(1);
    private const int MaxHoursKept = 100;

    private readonly record struct Hit(DateTime Time, EventType Type, string? User, string Path, int Status);

    private readonly Dictionary<string, Queue<Hit>> _byIp = new();
    private readonly Dictionary<string, Queue<Hit>> _byUser = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, UserBaseline> _baselines = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastPrune = DateTime.MinValue;

    private sealed class UserBaseline
    {
        public HashSet<string> KnownIps { get; } = new();
        public Queue<int> LoginHours { get; } = new();
    }

    public void Record(DateTime time, EventType type, string ip, string? user, string path, int status)
    {
        var hit = new Hit(time, type, user, path, status);
        Window(_byIp, ip).Enqueue(hit);
        if (user is not null) Window(_byUser, user).Enqueue(hit);

        if (time - _lastPrune > TimeSpan.FromMinutes(1))
        {
            Prune(time);
            _lastPrune = time;
        }
    }

    /// <summary>Learn from a successful login. Call after features for the login were computed.</summary>
    public void LearnSuccessfulLogin(string user, string ip, DateTime time)
    {
        if (!_baselines.TryGetValue(user, out var baseline)) _baselines[user] = baseline = new UserBaseline();
        baseline.KnownIps.Add(ip);
        baseline.LoginHours.Enqueue(time.Hour);
        if (baseline.LoginHours.Count > MaxHoursKept) baseline.LoginHours.Dequeue();
    }

    public double[] LoginFeatures(DateTime now, string ip, string? user) =>
    [
        Count(_byIp, ip, now, LongWindow, h => h.Type == EventType.LoginFailure),
        Recent(_byIp, ip, now, LongWindow)
            .Where(h => h.Type is EventType.LoginFailure or EventType.LoginSuccess && h.User is not null)
            .Select(h => h.User!.ToLowerInvariant()).Distinct().Count(),
        user is null ? 0 : Count(_byUser, user, now, LongWindow, h => h.Type == EventType.LoginFailure),
        IsNewIp(user, ip) ? 1 : 0,
        HoursFromUsual(user, now),
        Count(_byIp, ip, now, ShortWindow, _ => true),
    ];

    public double[] TrafficFeatures(DateTime now, string ip)
    {
        // Login attempts belong to the login model. Counting a mistyped password (401) here as well
        // would make an ordinary typo look like an attack on the API.
        var minute = Recent(_byIp, ip, now, ShortWindow).Where(h => !IsLoginType(h.Type)).ToList();
        var errors = minute.Count(h => h.Status >= 400);
        return
        [
            minute.Count,
            minute.Select(h => h.Path).Distinct().Count(),
            minute.Count == 0 ? 0 : Math.Round((double)errors / minute.Count, 3),
            minute.Count(h => h.Status == 404),
            Count(_byIp, ip, now, LongWindow, h => !IsLoginType(h.Type) && h.Status is 401 or 403),
        ];
    }

    private static bool IsLoginType(EventType type) => type is EventType.LoginSuccess or EventType.LoginFailure;

    public int CountForIp(string ip, DateTime now, TimeSpan window, Func<EventType, int, bool> match) =>
        Count(_byIp, ip, now, window, h => match(h.Type, h.Status));

    private bool IsNewIp(string? user, string ip) =>
        user is not null && _baselines.TryGetValue(user, out var b) && b.KnownIps.Count > 0 && !b.KnownIps.Contains(ip);

    /// <summary>Circular distance (0–12 h) between now and the user's average login hour.</summary>
    private double HoursFromUsual(string? user, DateTime now)
    {
        if (user is null || !_baselines.TryGetValue(user, out var b) || b.LoginHours.Count < 5) return 0;

        // Hours are on a clock face, so average them as angles: 23:00 and 01:00 average to 00:00, not 12:00.
        double sin = 0, cos = 0;
        foreach (var h in b.LoginHours)
        {
            var angle = h / 24.0 * 2 * Math.PI;
            sin += Math.Sin(angle);
            cos += Math.Cos(angle);
        }
        var meanHour = (Math.Atan2(sin, cos) / (2 * Math.PI) * 24 + 24) % 24;
        var diff = Math.Abs(now.Hour + now.Minute / 60.0 - meanHour);
        return Math.Round(Math.Min(diff, 24 - diff), 1);
    }

    private static Queue<Hit> Window(Dictionary<string, Queue<Hit>> map, string key)
    {
        if (!map.TryGetValue(key, out var q)) map[key] = q = new Queue<Hit>();
        return q;
    }

    private static IEnumerable<Hit> Recent(Dictionary<string, Queue<Hit>> map, string key, DateTime now, TimeSpan window) =>
        map.TryGetValue(key, out var q) ? q.Where(h => h.Time > now - window) : [];

    private static int Count(Dictionary<string, Queue<Hit>> map, string key, DateTime now, TimeSpan window, Func<Hit, bool> match) =>
        Recent(map, key, now, window).Count(match);

    private void Prune(DateTime now)
    {
        foreach (var map in new[] { _byIp, _byUser })
        {
            foreach (var (key, q) in map.ToList())
            {
                while (q.Count > 0 && q.Peek().Time < now - LongWindow) q.Dequeue();
                if (q.Count == 0) map.Remove(key);
            }
        }
    }
}
