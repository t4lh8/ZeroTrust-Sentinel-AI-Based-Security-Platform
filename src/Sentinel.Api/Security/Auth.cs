using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Sentinel.Api.Data;
using Sentinel.Shared;

namespace Sentinel.Api.Security;

public sealed class JwtOptions
{
    public const string Section = "Jwt";

    public string Issuer { get; set; } = "zerotrust-sentinel";
    public string Audience { get; set; } = "zerotrust-sentinel-dashboard";
    public string Key { get; set; } = "";
    public int LifetimeMinutes { get; set; } = 60;
}

public static class Policies
{
    public const string AnyRole = "AnyRole";
    public const string CanManageAlerts = "CanManageAlerts";
    public const string AdminOnly = "AdminOnly";
}

public static class Claims
{
    // Short, explicit claim names so the token reads the same in the API and in the Blazor client.
    public const string Name = "name";
    public const string Role = "role";
    public const string SecurityStamp = "sentinel:stamp";
}

public sealed class TokenService(IOptions<JwtOptions> jwtOptions)
{
    private readonly JwtOptions options = jwtOptions.Value;

    public LoginResponse CreateToken(User user)
    {
        var expires = DateTime.UtcNow.AddMinutes(options.LifetimeMinutes);
        var token = new JwtSecurityToken(
            issuer: options.Issuer,
            audience: options.Audience,
            claims:
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(Claims.Name, user.Username),
                new Claim(Claims.Role, user.Role),
                new Claim(Claims.SecurityStamp, user.SecurityStamp.ToString()),
            ],
            expires: expires,
            signingCredentials: new SigningCredentials(SigningKey(options), SecurityAlgorithms.HmacSha256));

        return new LoginResponse(new JwtSecurityTokenHandler().WriteToken(token), expires, user.Username, user.Role);
    }

    public static SymmetricSecurityKey SigningKey(JwtOptions options) => new(Encoding.UTF8.GetBytes(options.Key));
}

public static class AuthSetup
{
    public static IServiceCollection AddSentinelAuth(this IServiceCollection services)
    {
        // Bound lazily (not read while registering services) so every configuration source is honoured.
        services.AddOptions<JwtOptions>()
            .BindConfiguration(JwtOptions.Section)
            .Validate(o => Encoding.UTF8.GetByteCount(o.Key) >= 32,
                "Jwt:Key must be set to a random secret of at least 32 bytes (env var Jwt__Key).")
            .ValidateOnStart();

        services.AddSingleton<TokenService>();
        services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
        services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
            .Configure<IOptions<JwtOptions>>((o, jwtOptions) =>
            {
                var jwt = jwtOptions.Value;
                o.MapInboundClaims = false;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = jwt.Issuer,
                    ValidAudience = jwt.Audience,
                    IssuerSigningKey = TokenService.SigningKey(jwt),
                    ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = Claims.Name,
                    RoleClaimType = Claims.Role,
                };
                o.Events = new JwtBearerEvents
                {
                    // Browsers cannot set headers on WebSocket connections, so SignalR sends the token in the query string.
                    OnMessageReceived = ctx =>
                    {
                        var token = ctx.Request.Query["access_token"];
                        if (!string.IsNullOrEmpty(token) && ctx.HttpContext.Request.Path.StartsWithSegments("/hubs"))
                            ctx.Token = token;
                        return Task.CompletedTask;
                    },
                    OnTokenValidated = VerifyUserStillValid,
                };
            });

        services.AddAuthorizationBuilder()
            // Zero Trust: every endpoint requires an authenticated user unless it explicitly opts out.
            .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build())
            .AddPolicy(Policies.AnyRole, p => p.RequireRole(Roles.All))
            .AddPolicy(Policies.CanManageAlerts, p => p.RequireRole(Roles.Admin, Roles.Analyst))
            .AddPolicy(Policies.AdminOnly, p => p.RequireRole(Roles.Admin));

        return services;
    }

    /// <summary>
    /// Zero Trust: a valid signature is not enough. On every request, confirm the account still exists,
    /// is active, and has the same security stamp and role as when the token was issued.
    /// Deactivating a user or changing their role therefore revokes their tokens immediately.
    /// </summary>
    private static async Task VerifyUserStillValid(TokenValidatedContext ctx)
    {
        var principal = ctx.Principal!;
        var db = ctx.HttpContext.RequestServices.GetRequiredService<SentinelDbContext>();

        if (!Guid.TryParse(principal.FindFirstValue(JwtRegisteredClaimNames.Sub), out var userId) ||
            !Guid.TryParse(principal.FindFirstValue(Claims.SecurityStamp), out var stamp))
        {
            ctx.Fail("Token is missing required claims.");
            return;
        }

        var user = await db.Users.AsNoTracking()
            .Where(u => u.Id == userId)
            .Select(u => new { u.IsActive, u.SecurityStamp, u.Role })
            .FirstOrDefaultAsync(ctx.HttpContext.RequestAborted);

        if (user is null || !user.IsActive || user.SecurityStamp != stamp || user.Role != principal.FindFirstValue(Claims.Role))
            ctx.Fail("Token has been revoked.");
    }
}
