// Areas/Identity/Pages/Account/ResetPassword.cshtml.cs
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly PasswordHistoryService _passwordHistory;

        public ResetPasswordModel(UserManager<ApplicationUser> userManager, PasswordHistoryService passwordHistory)
        {
            _userManager = userManager;
            _passwordHistory = passwordHistory;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$",
                ErrorMessage = "Password must be at least 12 characters and include upper, lower, number, and special character.")]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            [Required]
            public string Code { get; set; }
        }

        public IActionResult OnGet(string code = null)
        {
            if (code == null)
                return BadRequest("A code must be supplied for password reset.");

            Input = new InputModel
            {
                Code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code))
            };
            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
                return RedirectToPage("./ResetPasswordConfirmation");

            // Avoid password reuse (last 2)
            var isReuse = await _passwordHistory.IsInRecentHistoryAsync(user, Input.Password, lastN: 2);
            if (isReuse)
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            var result = await _userManager.ResetPasswordAsync(user, Input.Code, Input.Password);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return Page();
            }

            // Refresh user to get latest PasswordHash, then record in history
            user = await _userManager.FindByEmailAsync(Input.Email);
            await _passwordHistory.RecordAsync(user);

            return RedirectToPage("./ResetPasswordConfirmation");
        }
    }
}
