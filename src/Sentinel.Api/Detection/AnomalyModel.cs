namespace Sentinel.Api.Detection;

/// <summary>
/// Wraps an <see cref="IsolationForest"/> with training statistics, used to explain scores and as a novelty guard.
/// Retraining swaps in a new immutable snapshot, so scoring never needs a lock.
///
/// Why the novelty guard: Isolation Forest only splits on values inside the training range. A feature that was
/// (almost) constant in training, such as "new IP for user" = 0, is never used to split, so a point with a
/// never-seen value (= 1) cannot be isolated by it. The final score is therefore the maximum of the forest score
/// and a z-score based novelty score that measures how far any feature lies outside the learned distribution.
/// </summary>
public sealed class AnomalyModel(string name, string[] featureNames, double threshold, int minSamples)
{
    private sealed record Snapshot(IsolationForest Forest, double[] Means, double[] StdDevs, int Samples, DateTime TrainedAtUtc);

    private volatile Snapshot? _snapshot;

    public string Name { get; } = name;
    public string[] FeatureNames { get; } = featureNames;
    public double Threshold { get; } = threshold;
    public int MinSamples { get; } = minSamples;
    public bool IsTrained => _snapshot is not null;
    public int TrainingSamples => _snapshot?.Samples ?? 0;
    public DateTime? TrainedAtUtc => _snapshot?.TrainedAtUtc;

    /// <returns>False when there is not enough data yet; the previous model (if any) is kept.</returns>
    public bool Train(IReadOnlyList<double[]> samples, int? seed = null)
    {
        if (samples.Count < MinSamples) return false;

        var dims = FeatureNames.Length;
        var means = new double[dims];
        var stdDevs = new double[dims];
        for (var f = 0; f < dims; f++)
        {
            var mean = samples.Average(s => s[f]);
            means[f] = mean;
            stdDevs[f] = Math.Sqrt(samples.Average(s => (s[f] - mean) * (s[f] - mean)));
        }

        var forest = IsolationForest.Train(samples, trees: 100, sampleSize: 256, seed: seed);
        _snapshot = new Snapshot(forest, means, stdDevs, samples.Count, DateTime.UtcNow);
        return true;
    }

    public double? Score(double[] features)
    {
        var s = _snapshot;
        if (s is null) return null;
        return Math.Max(s.Forest.Score(features), NoveltyScore(MaxZ(s, features)));
    }

    /// <summary>Maps the largest z-score onto the same 0–1 scale: z ≤ 2 is ordinary, z = 6 gives 0.7.</summary>
    public static double NoveltyScore(double z) => z <= 2 ? 0 : Math.Min(0.95, 0.5 + 0.05 * (z - 2));

    private static double Z(Snapshot s, double[] features, int f) =>
        Math.Abs(features[f] - s.Means[f]) / Math.Max(s.StdDevs[f], 0.1);

    private static double MaxZ(Snapshot s, double[] features) =>
        Enumerable.Range(0, features.Length).Max(f => Z(s, features, f));

    /// <summary>The features that deviate most from what the model saw in training, for the alert text.</summary>
    public IReadOnlyList<string> Explain(double[] features, int top = 3)
    {
        var s = _snapshot;
        if (s is null) return [];

        return Enumerable.Range(0, FeatureNames.Length)
            .Select(f => (f, z: Z(s, features, f)))
            .Where(x => x.z >= 2)
            .OrderByDescending(x => x.z)
            .Take(top)
            .Select(x => $"{FeatureNames[x.f]} = {Format(features[x.f])} (normal ≈ {Format(s.Means[x.f])})")
            .ToList();
    }

    private static string Format(double v) => v == Math.Floor(v) ? v.ToString("0") : v.ToString("0.##");

    public static string Serialize(double[] features) =>
        string.Join(';', features.Select(v => v.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture)));

    public static double[] Deserialize(string features) =>
        features.Split(';').Select(v => double.Parse(v, System.Globalization.CultureInfo.InvariantCulture)).ToArray();
}

/// <summary>The two models: one for authentication behaviour, one for HTTP traffic patterns.</summary>
public sealed class AnomalyModels(DetectionOptions options)
{
    public AnomalyModel Login { get; } = new("Login behaviour",
        ["failed logins from IP (10 min)", "distinct usernames from IP (10 min)", "failed logins for user (10 min)",
         "new IP for user", "hours from user's usual login time", "requests from IP (1 min)"],
        options.LoginAnomalyThreshold, options.MinTrainingSamples);

    public AnomalyModel Traffic { get; } = new("Traffic patterns",
        ["requests from IP (1 min)", "distinct paths from IP (1 min)", "error ratio from IP (1 min)",
         "404 responses to IP (1 min)", "401/403 responses to IP (10 min)"],
        options.TrafficAnomalyThreshold, options.MinTrainingSamples);

    public IEnumerable<AnomalyModel> All => [Login, Traffic];
}
