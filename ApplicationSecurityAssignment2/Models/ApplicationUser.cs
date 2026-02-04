using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace ApplicationSecurityAssignment2.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; } = string.Empty;

        [Required, MaxLength(50)]
        public string LastName { get; set; } = string.Empty;

        //Mobile is optional; IdentityUser.PhoneNumber is already defined

        [Required, MaxLength(200)]
        public string BillingAddress { get; set; } = string.Empty;

        // Allow special chars; still validate length, output-encode on display
        [Required, MaxLength(300)]
        public string ShippingAddress { get; set; } = string.Empty;

        // Store only server-generated filename (not user provided name)
        [MaxLength(260)]
        public string? PhotoFileName { get; set; }

        // Encrypted CC + IV (Base64)
        public string? EncryptedCreditCard { get; set; }
        public string? CreditCardIV { get; set; }
        public ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

    }
}
