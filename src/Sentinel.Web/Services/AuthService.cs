using System.Net.Http.Json;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.JSInterop;
using Sentinel.Shared;

namespace Sentinel.Web.Services;

/// <summary>
/// Holds the JWT for the session. It lives in sessionStorage (cleared when the tab closes)
/// rather than localStorage, which limits how long a stolen token stays on the machine.
/// </summary>
public sealed class AuthService(HttpClient http, IJSRuntime js) : AuthenticationStateProvider
{
    private const string StorageKey = "sentinel.token";
    private static readonly AuthenticationState Anonymous = new(new ClaimsPrincipal(new ClaimsIdentity()));

    private string? _token;
    private bool _loaded;

    public event Action? LoggedOut;

    public async Task<string?> GetTokenAsync()
    {
        if (!_loaded)
        {
            _token = await js.InvokeAsync<string?>("sessionStorage.getItem", StorageKey);
            _loaded = true;
        }

        if (_token is not null && ReadClaims(_token) is null)
        {
            // Expired or malformed: drop it.
            await ClearAsync();
        }
        return _token;
    }

    public async Task<string?> LoginAsync(string username, string password)
    {
        var response = await http.PostAsJsonAsync("api/auth/login", new LoginRequest(username, password));
        if (!response.IsSuccessStatusCode)
        {
            return (int)response.StatusCode switch
            {
                429 => "Too many login attempts. Wait a minute and try again.",
                401 => "Invalid username or password.",
                _ => "Login failed. Please try again.",
            };
        }

        var login = await response.Content.ReadFromJsonAsync<LoginResponse>();
        _token = login!.Token;
        _loaded = true;
        await js.InvokeVoidAsync("sessionStorage.setItem", StorageKey, _token);
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        return null;
    }

    public async Task LogoutAsync()
    {
        await ClearAsync();
        LoggedOut?.Invoke();
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var token = await GetTokenAsync();
        var claims = token is null ? null : ReadClaims(token);
        return claims is null ? Anonymous : new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity(claims, "jwt", "name", "role")));
    }

    private async Task ClearAsync()
    {
        _token = null;
        await js.InvokeVoidAsync("sessionStorage.removeItem", StorageKey);
        NotifyAuthenticationStateChanged(Task.FromResult(Anonymous));
    }

    /// <summary>
    /// Reads the token payload for display and routing only. The browser never decides access:
    /// the API validates the signature and the account on every request.
    /// </summary>
    private static List<Claim>? ReadClaims(string token)
    {
        try
        {
            var payload = token.Split('.')[1].Replace('-', '+').Replace('_', '/');
            payload = payload.PadRight(payload.Length + (4 - payload.Length % 4) % 4, '=');
            var values = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(Convert.FromBase64String(payload))!;

            if (values.TryGetValue("exp", out var exp) && DateTimeOffset.FromUnixTimeSeconds(exp.GetInt64()) <= DateTimeOffset.UtcNow)
                return null;

            return values.Where(kv => kv.Value.ValueKind == JsonValueKind.String)
                .Select(kv => new Claim(kv.Key, kv.Value.GetString()!))
                .ToList();
        }
        catch
        {
            return null;
        }
    }
}
