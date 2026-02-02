using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityAssignment2.Models
{
    public class ActiveSession
    {
        public int Id { get; set; }

        [Required, MaxLength(450)]
        public string UserId { get; set; } = string.Empty;

        [Required, MaxLength(64)]
        public string SessionToken { get; set; } = string.Empty; // GUID "N" string

        public DateTime IssuedAtUtc { get; set; } = DateTime.UtcNow;
        public DateTime ExpiresAtUtc { get; set; }

        public bool IsRevoked { get; set; } = false;
    }
}
