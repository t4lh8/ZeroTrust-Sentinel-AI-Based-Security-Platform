using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sentinel.Api.Data;
using Sentinel.Api.Monitoring;
using Sentinel.Api.Security;
using Sentinel.Shared;

namespace Sentinel.Api.Endpoints;

public static class AuthEndpoints
{
    public const string LoginRateLimitPolicy = "login";

    // Verifying against a dummy hash for unknown usernames keeps response times equal,
    // so attackers cannot discover which usernames exist by timing the login.
    private static readonly string DummyHash = new PasswordHasher<User>().HashPassword(null!, Guid.NewGuid().ToString());

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/auth").WithTags("Auth");

        group.MapPost("/login", Login).AllowAnonymous().RequireRateLimiting(LoginRateLimitPolicy);

        group.MapGet("/me", (ClaimsPrincipal user) =>
            new CurrentUserDto(user.Identity!.Name!, user.FindFirstValue(Claims.Role)!))
            .RequireAuthorization(Policies.AnyRole);
    }

    private static async Task<IResult> Login(
        LoginRequest request,
        HttpContext http,
        SentinelDbContext db,
        IPasswordHasher<User> hasher,
        TokenService tokens,
        AuditLogger audit,
        EventQueue queue)
    {
        http.MarkRecorded();
        var username = (request.Username ?? "").Trim();
        if (username.Length is 0 or > 64 || string.IsNullOrEmpty(request.Password) || request.Password.Length > 256)
            return Results.BadRequest(new { error = "Username and password are required." });

        var user = await db.Users.FirstOrDefaultAsync(u => u.Username == username);
        var passwordOk = hasher.VerifyHashedPassword(user!, user?.PasswordHash ?? DummyHash, request.Password)
            != PasswordVerificationResult.Failed;
        var valid = user is not null && user.IsActive && passwordOk;

        if (!valid)
        {
            http.Response.StatusCode = StatusCodes.Status401Unauthorized;
            queue.TryEnqueue(http.NewEvent(EventType.LoginFailure, username));
            await audit.LogAsync("auth.login", username, success: false, actor: username);
            return Results.Json(new { error = "Invalid username or password." }, statusCode: StatusCodes.Status401Unauthorized);
        }

        queue.TryEnqueue(http.NewEvent(EventType.LoginSuccess, user!.Username));
        await audit.LogAsync("auth.login", user.Username, success: true, actor: user.Username);
        return Results.Ok(tokens.CreateToken(user));
    }
}
