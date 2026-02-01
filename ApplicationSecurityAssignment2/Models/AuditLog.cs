using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityAssignment2.Models
{
    public class AuditLog
    {
        public int Id { get; set; }

        // Null allowed so you can log failed login attempts where user doesn't exist
        [MaxLength(450)]
        public string? UserId { get; set; }

        [MaxLength(256)]
        public string? Email { get; set; }

        [Required, MaxLength(50)]
        public string EventType { get; set; } = string.Empty; // e.g. REGISTER, LOGIN_SUCCESS, LOGIN_FAIL, LOGOUT, LOCKOUT

        [MaxLength(500)]
        public string? Details { get; set; }

        [MaxLength(45)]
        public string? IpAddress { get; set; }

        [MaxLength(512)]
        public string? UserAgent { get; set; }

        public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    }
}
