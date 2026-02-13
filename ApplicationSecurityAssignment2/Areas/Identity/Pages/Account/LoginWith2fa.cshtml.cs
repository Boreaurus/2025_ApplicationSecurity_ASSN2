// Areas/Identity/Pages/Account/LoginWith2fa.cshtml.cs
#nullable disable

using System;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using ApplicationSecurityAssignment2.Data;
using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class LoginWith2faModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ILogger<LoginWith2faModel> _logger;
        private readonly AuditLogService _audit;
        private readonly ApplicationDbContext _db;

        public LoginWith2faModel(
            SignInManager<ApplicationUser> signInManager,
            UserManager<ApplicationUser> userManager,
            ILogger<LoginWith2faModel> logger,
            AuditLogService audit,
            ApplicationDbContext db)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
            _audit = audit;
            _db = db;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public bool RememberMe { get; set; }
        public string ReturnUrl { get; set; }

        public class InputModel
        {
            [Required]
            [StringLength(7, MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Authenticator code")]
            public string TwoFactorCode { get; set; }

            [Display(Name = "Remember this machine")]
            public bool RememberMachine { get; set; }
        }

        public async Task<IActionResult> OnGetAsync(bool rememberMe, string returnUrl = null)
        {
            ReturnUrl = returnUrl ?? Url.Content("~/");
            RememberMe = rememberMe;

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("./Login");

            return Page();
        }

        public async Task<IActionResult> OnPostAsync(bool rememberMe, string returnUrl = null)
        {
            ReturnUrl = returnUrl ?? Url.Content("~/");
            RememberMe = rememberMe;

            if (!ModelState.IsValid)
                return Page();

            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user == null)
                return RedirectToPage("./Login");

            var authenticatorCode = Input.TwoFactorCode.Replace(" ", string.Empty).Replace("-", string.Empty);

            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(
                authenticatorCode,
                rememberMe,
                Input.RememberMachine);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in with 2FA.");

                // Single-session token policy (same as normal login)
                var token = Guid.NewGuid().ToString("N");
                HttpContext.Session.SetString("AuthToken", token);

                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(1)
                });

                var previous = _db.ActiveSessions.Where(s => s.UserId == user.Id && !s.IsRevoked);
                foreach (var s in previous) s.IsRevoked = true;

                _db.ActiveSessions.Add(new ActiveSession
                {
                    UserId = user.Id,
                    SessionToken = token,
                    IssuedAtUtc = DateTime.UtcNow,
                    ExpiresAtUtc = DateTime.UtcNow.AddMinutes(1),
                    IsRevoked = false
                });

                await _db.SaveChangesAsync();

                await _audit.WriteAsync(HttpContext, "LOGIN_2FA_SUCCESS", user.Id, user.Email, "2FA login succeeded.");
                return LocalRedirect(ReturnUrl);
            }

            if (result.IsLockedOut)
            {
                await _audit.WriteAsync(HttpContext, "LOCKOUT", user.Id, user.Email, "Locked out during 2FA.");
                return RedirectToPage("./Lockout");
            }

            await _audit.WriteAsync(HttpContext, "LOGIN_2FA_FAIL", user.Id, user.Email, "Invalid 2FA code.");
            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return Page();
        }
    }
}
