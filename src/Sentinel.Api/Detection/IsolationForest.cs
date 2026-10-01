namespace Sentinel.Api.Detection;

/// <summary>
/// Isolation Forest (Liu, Ting &amp; Zhou, 2008): an unsupervised anomaly detection algorithm.
///
/// Idea: build many random trees that split the data on a random feature at a random value.
/// Anomalies are "few and different", so they get isolated in very few splits (short paths),
/// while normal points sit in dense regions and need many splits (long paths).
///
/// The anomaly score is s(x) = 2^(-E[h(x)] / c(n)), where E[h(x)] is the average path length
/// over all trees and c(n) the average path length of an unsuccessful search in a binary tree.
/// s close to 1 means anomaly, values well below 0.5 mean normal.
/// </summary>
public sealed class IsolationForest
{
    private readonly Node[] _trees;
    private readonly int _sampleSize;

    private IsolationForest(Node[] trees, int sampleSize)
    {
        _trees = trees;
        _sampleSize = sampleSize;
    }

    public int TreeCount => _trees.Length;

    public static IsolationForest Train(IReadOnlyList<double[]> data, int trees = 100, int sampleSize = 256, int? seed = null)
    {
        if (data.Count < 2) throw new ArgumentException("Need at least two samples to train.", nameof(data));

        var random = seed is null ? new Random() : new Random(seed.Value);
        var psi = Math.Min(sampleSize, data.Count);
        var heightLimit = (int)Math.Ceiling(Math.Log2(psi));

        var forest = new Node[trees];
        for (var t = 0; t < trees; t++)
        {
            var sample = new double[psi][];
            for (var i = 0; i < psi; i++) sample[i] = data[random.Next(data.Count)];
            forest[t] = Build(sample, 0, heightLimit, random);
        }
        return new IsolationForest(forest, psi);
    }

    public double Score(double[] point)
    {
        var total = 0.0;
        foreach (var tree in _trees) total += PathLength(tree, point, 0);
        var meanPath = total / _trees.Length;
        return Math.Pow(2, -meanPath / AveragePathLength(_sampleSize));
    }

    private static Node Build(double[][] data, int depth, int heightLimit, Random random)
    {
        if (depth >= heightLimit || data.Length <= 1) return Node.Leaf(data.Length);

        // Only split on features that still vary inside this node.
        var dims = data[0].Length;
        var candidates = new List<(int Feature, double Min, double Max)>(dims);
        for (var f = 0; f < dims; f++)
        {
            double min = double.MaxValue, max = double.MinValue;
            foreach (var row in data)
            {
                if (row[f] < min) min = row[f];
                if (row[f] > max) max = row[f];
            }
            if (max > min) candidates.Add((f, min, max));
        }
        if (candidates.Count == 0) return Node.Leaf(data.Length);

        var (feature, lo, hi) = candidates[random.Next(candidates.Count)];
        var split = lo + random.NextDouble() * (hi - lo);

        var left = data.Where(r => r[feature] < split).ToArray();
        var right = data.Where(r => r[feature] >= split).ToArray();
        return Node.Split(feature, split,
            Build(left, depth + 1, heightLimit, random),
            Build(right, depth + 1, heightLimit, random));
    }

    private static double PathLength(Node node, double[] point, int depth)
    {
        while (!node.IsLeaf)
        {
            node = point[node.Feature] < node.SplitValue ? node.Left! : node.Right!;
            depth++;
        }
        // A leaf holding several points stands for an unbuilt subtree, so add its expected depth.
        return depth + AveragePathLength(node.Size);
    }

    /// <summary>c(n): average path length of an unsuccessful search in a binary search tree of n nodes.</summary>
    public static double AveragePathLength(int n)
    {
        if (n <= 1) return 0;
        if (n == 2) return 1;
        var harmonic = Math.Log(n - 1) + 0.5772156649; // Euler–Mascheroni constant
        return 2 * harmonic - 2.0 * (n - 1) / n;
    }

    private sealed class Node
    {
        public int Feature { get; private init; }
        public double SplitValue { get; private init; }
        public Node? Left { get; private init; }
        public Node? Right { get; private init; }
        public int Size { get; private init; }
        public bool IsLeaf => Left is null;

        public static Node Leaf(int size) => new() { Size = size };

        public static Node Split(int feature, double value, Node left, Node right) =>
            new() { Feature = feature, SplitValue = value, Left = left, Right = right };
    }
}
