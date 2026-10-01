namespace Sentinel.Api.Detection;

public sealed class DetectionOptions
{
    public const string Section = "Detection";

    public int BruteForceThreshold { get; set; } = 5;
    public int CredentialStuffingThreshold { get; set; } = 4;
    public int TargetedAccountThreshold { get; set; } = 8;
    public int PrivilegeProbingThreshold { get; set; } = 3;
    public int ScannerNotFoundThreshold { get; set; } = 15;
    public int FloodRateLimitedThreshold { get; set; } = 10;

    public double LoginAnomalyThreshold { get; set; } = 0.62;
    public double TrafficAnomalyThreshold { get; set; } = 0.72;
    public int MinTrainingSamples { get; set; } = 50;
    public int TrainingWindowDays { get; set; } = 7;
    public int RetrainIntervalMinutes { get; set; } = 5;
    public int RetentionDays { get; set; } = 14;

    /// <summary>Fake credentials planted in honeypot responses. Any login attempt with them is an attacker.</summary>
    public string[] Honeytokens { get; set; } = ["backup_admin", "svc_deploy"];
}
