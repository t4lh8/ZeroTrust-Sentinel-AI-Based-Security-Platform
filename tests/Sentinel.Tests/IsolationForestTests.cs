using Sentinel.Api.Detection;

namespace Sentinel.Tests;

public class IsolationForestTests
{
    private static List<double[]> NormalCluster(int count, int seed)
    {
        var random = new Random(seed);
        return Enumerable.Range(0, count)
            .Select(_ => new[] { 10 + random.NextDouble() * 2, 5 + random.NextDouble(), random.NextDouble() })
            .ToList();
    }

    [Fact]
    public void Outlier_scores_higher_than_normal_points()
    {
        var forest = IsolationForest.Train(NormalCluster(500, seed: 1), seed: 42);

        var normal = forest.Score([11, 5.5, 0.5]);
        var outlier = forest.Score([40, 30, 9]);

        Assert.True(outlier > 0.6, $"outlier score {outlier:0.000} should be > 0.6");
        Assert.True(normal < 0.55, $"normal score {normal:0.000} should be < 0.55");
        Assert.True(outlier > normal);
    }

    [Fact]
    public void Scores_are_between_zero_and_one()
    {
        var forest = IsolationForest.Train(NormalCluster(300, seed: 2), seed: 7);
        foreach (var point in NormalCluster(50, seed: 3).Append([1000, -1000, 1000]))
        {
            var score = forest.Score(point);
            Assert.InRange(score, 0, 1);
        }
    }

    [Fact]
    public void Same_seed_gives_same_model()
    {
        var data = NormalCluster(300, seed: 4);
        var a = IsolationForest.Train(data, seed: 99);
        var b = IsolationForest.Train(data, seed: 99);
        Assert.Equal(a.Score([20, 9, 3]), b.Score([20, 9, 3]));
    }

    [Fact]
    public void Constant_data_does_not_crash()
    {
        var data = Enumerable.Repeat(new double[] { 1, 1, 1 }, 100).ToList();
        var forest = IsolationForest.Train(data, seed: 1);
        Assert.InRange(forest.Score([1, 1, 1]), 0, 1);
    }

    [Theory]
    [InlineData(1, 0)]
    [InlineData(2, 1)]
    [InlineData(256, 10.24)]
    public void Average_path_length_matches_paper(int n, double expected) =>
        Assert.Equal(expected, IsolationForest.AveragePathLength(n), precision: 2);

    [Fact]
    public void Model_explains_which_features_are_unusual()
    {
        var model = new AnomalyModel("test", ["requests", "errors", "ratio"], threshold: 0.6, minSamples: 10);
        Assert.True(model.Train(NormalCluster(200, seed: 5), seed: 1));

        var reasons = model.Explain([11, 5.5, 8]);

        Assert.Single(reasons);
        Assert.StartsWith("ratio", reasons[0]);
    }

    [Fact]
    public void Novelty_guard_flags_values_never_seen_in_training()
    {
        // The third feature is always 0 in training, so the forest alone cannot split on it.
        var random = new Random(8);
        var data = Enumerable.Range(0, 200).Select(_ => new[] { 10 + random.NextDouble(), 5 + random.NextDouble(), 0.0 }).ToList();
        var model = new AnomalyModel("test", ["a", "b", "new IP"], threshold: 0.6, minSamples: 10);
        model.Train(data, seed: 1);

        Assert.True(model.Score([10.5, 5.5, 0]) < 0.6);
        Assert.True(model.Score([10.5, 5.5, 1]) >= 0.6);
    }

    [Theory]
    [InlineData(1.5, 0)]
    [InlineData(6, 0.7)]
    [InlineData(100, 0.95)]
    public void Novelty_score_scale(double z, double expected) =>
        Assert.Equal(expected, AnomalyModel.NoveltyScore(z), precision: 3);

    [Fact]
    public void Model_waits_for_enough_samples()
    {
        var model = new AnomalyModel("test", ["a", "b", "c"], threshold: 0.6, minSamples: 50);
        Assert.False(model.Train(NormalCluster(10, seed: 6)));
        Assert.False(model.IsTrained);
        Assert.Null(model.Score([1, 2, 3]));
    }
}
