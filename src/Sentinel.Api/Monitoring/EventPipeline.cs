using System.Threading.Channels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Data;
using Sentinel.Api.Detection;
using Sentinel.Shared;

namespace Sentinel.Api.Monitoring;

/// <summary>
/// Queue between request handling and detection. Requests only enqueue (cheap, never blocks the response);
/// a single background worker does the analysis, persistence and live broadcasting.
/// </summary>
public sealed class EventQueue
{
    private readonly Channel<SecurityEvent> _channel = Channel.CreateBounded<SecurityEvent>(
        new BoundedChannelOptions(50_000) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

    private long _pending;

    public ChannelReader<SecurityEvent> Reader => _channel.Reader;

    /// <summary>Number of events queued or being processed.</summary>
    public long Pending => Interlocked.Read(ref _pending);

    /// <summary>Non-blocking write used on the request path. Drops the event if the queue is full.</summary>
    public bool TryEnqueue(SecurityEvent ev)
    {
        if (!_channel.Writer.TryWrite(ev)) return false;
        Interlocked.Increment(ref _pending);
        return true;
    }

    /// <summary>Waits for space; used for bulk loads such as the demo history backfill.</summary>
    public async ValueTask EnqueueAsync(SecurityEvent ev, CancellationToken ct)
    {
        await _channel.Writer.WriteAsync(ev, ct);
        Interlocked.Increment(ref _pending);
    }

    internal void MarkProcessed(int count) => Interlocked.Add(ref _pending, -count);
}

[Authorize]
public sealed class AlertHub : Hub;

public sealed class EventProcessor(
    EventQueue queue,
    ThreatDetector detector,
    IServiceScopeFactory scopes,
    IHubContext<AlertHub> hub,
    ILogger<EventProcessor> logger) : BackgroundService
{
    private const int BatchSize = 500;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await LoadBaselinesAsync(stoppingToken);

        var batch = new List<SecurityEvent>(BatchSize);
        while (await queue.Reader.WaitToReadAsync(stoppingToken))
        {
            batch.Clear();
            while (batch.Count < BatchSize && queue.Reader.TryRead(out var ev)) batch.Add(ev);

            try
            {
                await ProcessBatchAsync(batch, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Failed to process a batch of {Count} security events", batch.Count);
            }
            finally
            {
                queue.MarkProcessed(batch.Count);
            }
        }
    }

    private async Task ProcessBatchAsync(List<SecurityEvent> batch, CancellationToken ct)
    {
        var alerts = new List<Alert>();
        foreach (var ev in batch) alerts.AddRange(detector.Analyze(ev));

        using (var scope = scopes.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
            db.Events.AddRange(batch);
            db.Alerts.AddRange(alerts);
            await db.SaveChangesAsync(ct);
        }

        foreach (var alert in alerts)
            logger.LogWarning("ALERT [{Severity}] {Category}: {Title} (source {Ip})", alert.Severity, alert.Category, alert.Title, alert.SourceIp);

        // Historical (backfilled) events are not "live", so only push recent ones to dashboards.
        var cutoff = DateTime.UtcNow.AddMinutes(-1);
        foreach (var ev in batch.Where(e => e.TimestampUtc > cutoff).TakeLast(50))
            await hub.Clients.All.SendAsync(HubMethods.EventRecorded, ev.ToDto(), ct);
        foreach (var alert in alerts.Where(a => a.CreatedAtUtc > cutoff))
            await hub.Clients.All.SendAsync(HubMethods.AlertRaised, alert.ToDto(), ct);
    }

    /// <summary>After a restart, rebuild each user's known IPs and usual login hours from stored logins.</summary>
    private async Task LoadBaselinesAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var since = DateTime.UtcNow.AddDays(-30);
        var logins = await db.Events
            .Where(e => e.Type == EventType.LoginSuccess && e.TimestampUtc > since && e.Username != null)
            .OrderBy(e => e.TimestampUtc)
            .Take(20_000)
            .Select(e => new { e.Username, e.SourceIp, e.TimestampUtc })
            .ToListAsync(ct);

        foreach (var l in logins) detector.LearnBaseline(l.Username!, l.SourceIp, l.TimestampUtc);
        if (logins.Count > 0) logger.LogInformation("Loaded login baselines from {Count} historical logins", logins.Count);
    }
}

/// <summary>Periodically retrains both anomaly models on recent history and enforces data retention.</summary>
public sealed class ModelTrainer(
    AnomalyModels models,
    DetectionOptions options,
    IServiceScopeFactory scopes,
    ILogger<ModelTrainer> logger) : BackgroundService
{
    private readonly SemaphoreSlim _trainLock = new(1, 1);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMinutes(options.RetrainIntervalMinutes));
        do
        {
            try
            {
                await TrainNowAsync(stoppingToken);
                await ApplyRetentionAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Model training failed");
            }
        } while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    public async Task TrainNowAsync(CancellationToken ct)
    {
        await _trainLock.WaitAsync(ct);
        try
        {
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
            var since = DateTime.UtcNow.AddDays(-options.TrainingWindowDays);

            await TrainAsync(db, models.Login, since, login: true, ct);
            await TrainAsync(db, models.Traffic, since, login: false, ct);
        }
        finally
        {
            _trainLock.Release();
        }
    }

    private async Task TrainAsync(SentinelDbContext db, AnomalyModel model, DateTime since, bool login, CancellationToken ct)
    {
        var query = db.Events.Where(e => e.TimestampUtc > since && e.Features != null);
        query = login
            ? query.Where(e => e.Type == EventType.LoginSuccess || e.Type == EventType.LoginFailure)
            : query.Where(e => e.Type != EventType.LoginSuccess && e.Type != EventType.LoginFailure);

        var rows = await query.OrderByDescending(e => e.TimestampUtc).Take(5000).Select(e => e.Features!).ToListAsync(ct);
        var samples = rows.Select(AnomalyModel.Deserialize).Where(f => f.Length == model.FeatureNames.Length).ToList();

        if (model.Train(samples))
            logger.LogInformation("Trained '{Model}' on {Count} samples", model.Name, samples.Count);
        else
            logger.LogInformation("'{Model}' waiting for data: {Count}/{Min} samples", model.Name, samples.Count, model.MinSamples);
    }

    private async Task ApplyRetentionAsync(CancellationToken ct)
    {
        using var scope = scopes.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var cutoff = DateTime.UtcNow.AddDays(-options.RetentionDays);
        var removed = await db.Events.Where(e => e.TimestampUtc < cutoff).ExecuteDeleteAsync(ct);
        if (removed > 0) logger.LogInformation("Retention: deleted {Count} events older than {Days} days", removed, options.RetentionDays);
    }
}
