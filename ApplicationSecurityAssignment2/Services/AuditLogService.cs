using ApplicationSecurityAssignment2.Data;
using ApplicationSecurityAssignment2.Models;

namespace ApplicationSecurityAssignment2.Services
{
    public class AuditLogService
    {
        private readonly ApplicationDbContext _db;

        public AuditLogService(ApplicationDbContext db)
        {
            _db = db;
        }

        public async Task WriteAsync(HttpContext http, string eventType, string? userId, string? email, string? details = null)
        {
            var ip = http.Connection.RemoteIpAddress?.ToString();

            var ua = http.Request.Headers.UserAgent.ToString();

            var log = new AuditLog
            {
                EventType = eventType,
                UserId = userId,
                Email = email,
                Details = details,
                IpAddress = ip,
                UserAgent = ua
            };

            _db.AuditLogs.Add(log);
            await _db.SaveChangesAsync();
        }
    }
}
