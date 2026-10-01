using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;

namespace Sentinel.Web.Services;

public sealed class ApiException(string message) : Exception(message);

/// <summary>Typed calls to the API. Attaches the bearer token and logs out when the server rejects it.</summary>
public sealed class ApiClient(HttpClient http, AuthService auth)
{
    public Task<T?> GetAsync<T>(string url) => SendAsync<T>(HttpMethod.Get, url, null);

    public Task<T?> PostAsync<T>(string url, object? body = null) => SendAsync<T>(HttpMethod.Post, url, body);

    private async Task<T?> SendAsync<T>(HttpMethod method, string url, object? body)
    {
        using var request = new HttpRequestMessage(method, url);
        var token = await auth.GetTokenAsync();
        if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        if (body is not null) request.Content = JsonContent.Create(body);

        using var response = await http.SendAsync(request);
        switch (response.StatusCode)
        {
            case HttpStatusCode.Unauthorized:
                // Token expired or revoked server-side (e.g. account deactivated): the session ends now.
                await auth.LogoutAsync();
                throw new ApiException("Your session has ended. Please log in again.");
            case HttpStatusCode.Forbidden:
                throw new ApiException("Your role does not allow this action.");
            case HttpStatusCode.TooManyRequests:
                throw new ApiException("Rate limit reached. Slow down and try again shortly.");
            case HttpStatusCode.BadRequest:
                var problem = await response.Content.ReadFromJsonAsync<ErrorBody>();
                throw new ApiException(string.Join(" ", problem?.Errors ?? [problem?.Error ?? "Invalid request."]));
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>();
    }

    private sealed record ErrorBody(string? Error, string[]? Errors);
}
