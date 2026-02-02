// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ApplicationSecurityAssignment2.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using ApplicationSecurityAssignment2.Services;
using ApplicationSecurityAssignment2.Data;
using Microsoft.AspNetCore.Http;



namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuditLogService _audit;
        private readonly ApplicationDbContext _db;


        public LoginModel(
            SignInManager<ApplicationUser> signInManager, 
            ILogger<LoginModel> logger,
            UserManager<ApplicationUser> userManager,
            AuditLogService audit,
            ApplicationDbContext db)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _audit = audit;
            _db = db;
        }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [BindProperty]
        public InputModel Input { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public string ReturnUrl { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        [TempData]
        public string ErrorMessage { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            /// <summary>
            ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
            ///     directly from your code. This API may change or be removed in future releases.
            /// </summary>
            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return Page();

            // Find user early for logging (may be null)
            var user = await _userManager.FindByEmailAsync(Input.Email);

            // IMPORTANT: lockoutOnFailure must be true to enforce lockout after failures
            var result = await _signInManager.PasswordSignInAsync(
                Input.Email,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                _logger.LogInformation("User logged in.");

                var token = Guid.NewGuid().ToString("N"); // session token per login
                HttpContext.Session.SetString("AuthToken", token);

                // cookie copy(Auth token) to match session
                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(5)
                });

                // store to DB for multi-login detection
                if (user != null)
                {
                    // Revoke previous active sessions for this user (single-session policy)
                    var previous = _db.ActiveSessions.Where(s => s.UserId == user.Id && !s.IsRevoked);
                    foreach (var s in previous) s.IsRevoked = true;

                    _db.ActiveSessions.Add(new ActiveSession
                    {
                        UserId = user.Id,
                        SessionToken = token,
                        IssuedAtUtc = DateTime.UtcNow,
                        ExpiresAtUtc = DateTime.UtcNow.AddMinutes(5),
                        IsRevoked = false
                    });

                    await _db.SaveChangesAsync();
                }

                await _audit.WriteAsync(HttpContext, "LOGIN_SUCCESS", user?.Id, Input.Email, "Login succeeded.");
                return LocalRedirect(returnUrl);

            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                await _audit.WriteAsync(HttpContext, "LOCKOUT", user?.Id, Input.Email, "Account locked out due to failed attempts.");
                return RedirectToPage("./Lockout");
            }

            if (result.RequiresTwoFactor)
            {
                await _audit.WriteAsync(HttpContext, "LOGIN_2FA_REQUIRED", user?.Id, Input.Email, "2FA required but not implemented.");
                ModelState.AddModelError(string.Empty, "Two-factor authentication is required for this account.");
                return Page();
            }

            _logger.LogWarning("Invalid login attempt.");
            await _audit.WriteAsync(HttpContext, "LOGIN_FAIL", user?.Id, Input.Email, "Invalid credentials.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }

    }
}
