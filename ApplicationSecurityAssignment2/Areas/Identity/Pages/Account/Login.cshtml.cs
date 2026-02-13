// Areas/Identity/Pages/Account/Login.cshtml.cs
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using ApplicationSecurityAssignment2.Data;
using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LoginModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuditLogService _audit;
        private readonly ApplicationDbContext _db;

        private readonly RecaptchaService _recaptcha;
        private readonly IConfiguration _config;

        private readonly PasswordHistoryService _passwordHistory;

        public LoginModel(
            SignInManager<ApplicationUser> signInManager,
            ILogger<LoginModel> logger,
            UserManager<ApplicationUser> userManager,
            AuditLogService audit,
            ApplicationDbContext db,
            RecaptchaService recaptcha,
            IConfiguration config,
            PasswordHistoryService passwordHistory)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _audit = audit;
            _db = db;

            _recaptcha = recaptcha;
            _config = config;

            _passwordHistory = passwordHistory;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        // token posted from the hidden input in Login.cshtml
        [BindProperty]
        public string RecaptchaToken { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }
        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
                ModelState.AddModelError(string.Empty, ErrorMessage);

            returnUrl ??= Url.Content("~/");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
            ReturnUrl = returnUrl;
        }

        private async Task<IActionResult> EnforceMaxPasswordAgeOrNullAsync(ApplicationUser user)
        {
            var maxAgeDays = _config.GetValue<int>("PasswordPolicy:MaxAgeDays");
            if (maxAgeDays <= 0) return null;

            var lastChanged = await _passwordHistory.GetLastChangedUtcAsync(user.Id);
            if (lastChanged.HasValue &&
                DateTime.UtcNow - lastChanged.Value > TimeSpan.FromDays(maxAgeDays))
            {
                await _audit.WriteAsync(HttpContext, "LOGIN_PASSWORD_EXPIRED", user.Id, user.Email,
                    $"Password expired (older than {maxAgeDays} days). Forced reset.");

                TempData["ErrorMessage"] = "Your password has expired. Please reset your password.";
                return RedirectToPage("./ForgotPassword");
            }

            return null;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return Page();

            // reCAPTCHA v3 (server-side)
           
            var minScore = 0.5;
            var minScoreStr = _config["Recaptcha:MinimumScore"];
            if (!string.IsNullOrWhiteSpace(minScoreStr) && double.TryParse(minScoreStr, out var ms))
                minScore = ms;

            var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var (ok, score, errors) = await _recaptcha.VerifyAsync(RecaptchaToken, "login", remoteIp);

            if (!ok || score < minScore)
            {
                _logger.LogWarning("reCAPTCHA failed (login). ok={Ok}, score={Score}, errors={Errors}",
                    ok, score, string.Join(",", errors ?? Array.Empty<string>()));

                await _audit.WriteAsync(HttpContext, "LOGIN_RECAPTCHA_FAIL", null, Input.Email, "reCAPTCHA failed.");
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            // Find user early for logging and checks (may be null)
            var user = await _userManager.FindByEmailAsync(Input.Email);

            var result = await _signInManager.PasswordSignInAsync(
                Input.Email,
                Input.Password,
                Input.RememberMe,
                lockoutOnFailure: true);

            if (result.Succeeded)
            {
                if (user != null)
                {
                    var expiredResult = await EnforceMaxPasswordAgeOrNullAsync(user);
                    if (expiredResult != null)
                    {
                        await _signInManager.SignOutAsync();
                        return expiredResult;
                    }
                }

                _logger.LogInformation("User logged in.");

                var token = Guid.NewGuid().ToString("N");
                HttpContext.Session.SetString("AuthToken", token);

                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true,
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTimeOffset.UtcNow.AddMinutes(1)
                });

                if (user != null)
                {
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
                }

                await _audit.WriteAsync(HttpContext, "LOGIN_SUCCESS", user?.Id, Input.Email, "Login succeeded.");
                return LocalRedirect(returnUrl);
            }

            if (result.RequiresTwoFactor)
            {
                if (user != null)
                {
                    var expiredResult = await EnforceMaxPasswordAgeOrNullAsync(user);
                    if (expiredResult != null)
                        return expiredResult;
                }

                await _audit.WriteAsync(HttpContext, "LOGIN_2FA_REQUIRED", user?.Id, Input.Email, "2FA required.");
                return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
            }

            if (result.IsLockedOut)
            {
                _logger.LogWarning("User account locked out.");
                await _audit.WriteAsync(HttpContext, "LOCKOUT", user?.Id, Input.Email, "Account locked out due to failed attempts.");
                return RedirectToPage("./Lockout");
            }

            _logger.LogWarning("Invalid login attempt.");
            await _audit.WriteAsync(HttpContext, "LOGIN_FAIL", user?.Id, Input.Email, "Invalid credentials.");
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return Page();
        }
    }
}
