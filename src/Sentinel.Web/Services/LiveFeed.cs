using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.SignalR.Client;
using Sentinel.Shared;

namespace Sentinel.Web.Services;

/// <summary>One SignalR connection per session that pushes new alerts and events to every page.</summary>
public sealed class LiveFeed(NavigationManager navigation, AuthService auth) : IAsyncDisposable
{
    private HubConnection? _connection;

    public event Action<AlertDto>? AlertRaised;
    public event Action<SecurityEventDto>? EventRecorded;
    public event Action? StateChanged;

    public HubConnectionState State => _connection?.State ?? HubConnectionState.Disconnected;

    public async Task StartAsync()
    {
        if (_connection is not null) return;

        _connection = new HubConnectionBuilder()
            .WithUrl(navigation.ToAbsoluteUri("/hubs/alerts"), o => o.AccessTokenProvider = auth.GetTokenAsync)
            .WithAutomaticReconnect()
            .Build();

        _connection.On<AlertDto>(HubMethods.AlertRaised, a => AlertRaised?.Invoke(a));
        _connection.On<SecurityEventDto>(HubMethods.EventRecorded, e => EventRecorded?.Invoke(e));
        _connection.Reconnecting += _ => Notify();
        _connection.Reconnected += _ => Notify();
        _connection.Closed += _ => Notify();

        try
        {
            await _connection.StartAsync();
        }
        catch
        {
            // The dashboard still works by polling; the status chip shows the feed is offline.
        }
        StateChanged?.Invoke();
    }

    public async Task StopAsync()
    {
        if (_connection is null) return;
        await _connection.DisposeAsync();
        _connection = null;
        StateChanged?.Invoke();
    }

    private Task Notify()
    {
        StateChanged?.Invoke();
        return Task.CompletedTask;
    }

    public ValueTask DisposeAsync() => _connection?.DisposeAsync() ?? ValueTask.CompletedTask;
}
