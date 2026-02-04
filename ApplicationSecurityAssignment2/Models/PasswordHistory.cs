using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityAssignment2.Models
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } = string.Empty;

        [Required]
        public string PasswordHash { get; set; } = string.Empty;

        public DateTime ChangedAtUtc { get; set; } = DateTime.UtcNow;

        // optional navigation
        public ApplicationUser? User { get; set; }
    }
}
