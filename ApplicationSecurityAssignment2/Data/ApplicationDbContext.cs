using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ApplicationSecurityAssignment2.Models;

namespace ApplicationSecurityAssignment2.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        

        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }
        public DbSet<AuditLog> AuditLogs { get; set; } = default!;
        public DbSet<ActiveSession> ActiveSessions { get; set; } = default!;
    }
}
