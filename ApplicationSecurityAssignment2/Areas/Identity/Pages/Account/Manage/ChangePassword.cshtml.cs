// Areas/Identity/Pages/Account/Manage/ChangePassword.cshtml.cs
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Threading.Tasks;
using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account.Manage
{
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<ChangePasswordModel> _logger;
        private readonly PasswordHistoryService _passwordHistory;
        private readonly IConfiguration _config;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            ILogger<ChangePasswordModel> logger,
            PasswordHistoryService passwordHistory,
            IConfiguration config)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _passwordHistory = passwordHistory;
            _config = config;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        [TempData]
        public string StatusMessage { get; set; }

        public class InputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current password")]
            public string OldPassword { get; set; }

            [Required]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$",
                ErrorMessage = "Password must be at least 12 characters and include upper, lower, number, and special character.")]
            [DataType(DataType.Password)]
            [Display(Name = "New password")]
            public string NewPassword { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm new password")]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            var hasPassword = await _userManager.HasPasswordAsync(user);
            if (!hasPassword)
                return RedirectToPage("./SetPassword");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
                return Page();

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return NotFound($"Unable to load user with ID '{_userManager.GetUserId(User)}'.");

            // void password reuse (last 2)
            var isReuse = await _passwordHistory.IsInRecentHistoryAsync(user, Input.NewPassword, lastN: 2);
            if (isReuse)
            {
                ModelState.AddModelError(string.Empty, "You cannot reuse your last 2 passwords.");
                return Page();
            }

            // Minimum password age (optional: if config is missing, defaults to 0 = no restriction)
            var minAgeMinutes = _config.GetValue<int>("PasswordPolicy:MinAgeMinutes");
            if (minAgeMinutes > 0)
            {
                var lastChanged = await _passwordHistory.GetLastChangedUtcAsync(user.Id);

                if (lastChanged.HasValue &&
                    DateTime.UtcNow - lastChanged.Value < TimeSpan.FromMinutes(minAgeMinutes))
                {
                    ModelState.AddModelError(string.Empty,
                        $"You can only change your password after {minAgeMinutes} minutes from the last change.");
                    return Page();
                }
            }

            // Perform change (Identity verifies old password)
            var result = await _userManager.ChangePasswordAsync(user, Input.OldPassword, Input.NewPassword);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return Page();
            }

            // Record the new password hash + keep only last 2 (centralized)
            user = await _userManager.GetUserAsync(User); // refresh so PasswordHash is current
            await _passwordHistory.RecordAsync(user);

            await _signInManager.RefreshSignInAsync(user);
            _logger.LogInformation("User changed their password successfully.");
            StatusMessage = "Your password has been changed.";

            return RedirectToPage();
        }
    }
}
