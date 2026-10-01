using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sentinel.Shared;

namespace Sentinel.Api.Data;

public sealed class SeedOptions
{
    public const string Section = "Seed";

    public string AdminUsername { get; set; } = "admin";
    public string? AdminPassword { get; set; }
    public string? AnalystPassword { get; set; }
    public string? ViewerPassword { get; set; }
}

public static class DatabaseSetup
{
    public static IServiceCollection AddSentinelDatabase(this IServiceCollection services, IConfiguration config)
    {
        var provider = config["Database:Provider"] ?? "Postgres";
        var connection = config.GetConnectionString("Sentinel")
            ?? throw new InvalidOperationException("ConnectionStrings:Sentinel is not configured.");

        services.AddDbContext<SentinelDbContext>(o =>
        {
            if (provider.Equals("Sqlite", StringComparison.OrdinalIgnoreCase)) o.UseSqlite(connection);
            else o.UseNpgsql(connection);
        });
        return services;
    }

    /// <summary>Creates the schema and the initial accounts. Passwords come from configuration, never from code.</summary>
    public static async Task InitializeDatabaseAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<SentinelDbContext>();
        var hasher = scope.ServiceProvider.GetRequiredService<IPasswordHasher<User>>();
        var seed = app.Configuration.GetSection(SeedOptions.Section).Get<SeedOptions>() ?? new SeedOptions();
        var logger = app.Logger;

        // The database container may still be starting, so retry for a while.
        for (var attempt = 1; ; attempt++)
        {
            try
            {
                await db.Database.EnsureCreatedAsync();
                break;
            }
            catch (Exception ex) when (attempt < 15)
            {
                logger.LogWarning("Database not ready (attempt {Attempt}): {Message}", attempt, ex.Message);
                await Task.Delay(TimeSpan.FromSeconds(2));
            }
        }

        if (await db.Users.AnyAsync()) return;

        if (string.IsNullOrWhiteSpace(seed.AdminPassword))
            throw new InvalidOperationException("Seed:AdminPassword must be set on first start (env var Seed__AdminPassword).");

        AddUser(seed.AdminUsername, seed.AdminPassword, Roles.Admin);
        if (!string.IsNullOrWhiteSpace(seed.AnalystPassword)) AddUser("analyst", seed.AnalystPassword, Roles.Analyst);
        if (!string.IsNullOrWhiteSpace(seed.ViewerPassword)) AddUser("viewer", seed.ViewerPassword, Roles.Viewer);
        await db.SaveChangesAsync();
        logger.LogInformation("Created initial accounts");

        void AddUser(string username, string password, string role)
        {
            var user = new User { Username = username, Role = role, PasswordHash = "" };
            user.PasswordHash = hasher.HashPassword(user, password);
            db.Users.Add(user);
        }
    }
}
