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
        public DbSet<PasswordHistory> PasswordHistories { get; set; } = default!;
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<PasswordHistory>()
                .HasIndex(p => new { p.UserId, p.ChangedAtUtc });

            builder.Entity<PasswordHistory>()
                .HasOne(p => p.User)
                .WithMany(u => u.PasswordHistories)
                .HasForeignKey(p => p.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }


    }
}
