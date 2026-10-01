using Sentinel.Api.Data;
using Sentinel.Api.Monitoring;

namespace Sentinel.Api.Security;

public sealed class AuditLogger(SentinelDbContext db, IHttpContextAccessor http)
{
    public string? CurrentUser => http.HttpContext?.User.Identity?.Name;

    public async Task LogAsync(string action, string target, bool success, string? actor = null)
    {
        var context = http.HttpContext;
        db.AuditLogs.Add(new AuditLog
        {
            Actor = actor ?? context?.User.Identity?.Name ?? "anonymous",
            Action = action,
            Target = target.Length <= 256 ? target : target[..256],
            SourceIp = context?.ClientIp() ?? "system",
            Success = success,
        });
        await db.SaveChangesAsync();
    }
}
