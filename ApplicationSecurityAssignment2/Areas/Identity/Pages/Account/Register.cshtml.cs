// Areas/Identity/Pages/Account/Register.cshtml.cs
// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using ApplicationSecurityAssignment2.Data;
using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class RegisterModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IUserStore<ApplicationUser> _userStore;
        private readonly IUserEmailStore<ApplicationUser> _emailStore;
        private readonly ILogger<RegisterModel> _logger;
        private readonly IEmailSender _emailSender;
        private readonly AesEncryptionService _aes;
        private readonly AuditLogService _audit;
        private readonly ApplicationDbContext _db;
        private readonly IWebHostEnvironment _env;

        private readonly RecaptchaService _recaptcha;
        private readonly IConfiguration _config;

        private readonly PasswordHistoryService _passwordHistory;

        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            AesEncryptionService aes,
            AuditLogService audit,
            ApplicationDbContext db,
            IWebHostEnvironment env,
            RecaptchaService recaptcha,
            IConfiguration config,
            PasswordHistoryService passwordHistory)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _aes = aes;
            _audit = audit;
            _db = db;
            _env = env;

            _recaptcha = recaptcha;
            _config = config;

            _passwordHistory = passwordHistory;
        }

        private static bool LooksLikeCardNumber(string input)
        {
            var digits = new string(input.Where(char.IsDigit).ToArray());
            return digits.Length is >= 12 and <= 19;
        }

        private static async Task<bool> IsJpegAsync(IFormFile file)
        {
            if (file.Length < 2) return false;

            using var stream = file.OpenReadStream();
            var header = new byte[2];
            var read = await stream.ReadAsync(header, 0, 2);
            return read == 2 && header[0] == 0xFF && header[1] == 0xD8;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        // token posted from the hidden field in Register.cshtml
        [BindProperty]
        public string RecaptchaToken { get; set; }

        public string ReturnUrl { get; set; }
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$",
                ErrorMessage = "Password must be at least 12 characters and include upper, lower, number, and special character.")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; }

            [DataType(DataType.Password)]
            [Display(Name = "Confirm password")]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            [Required, MaxLength(50)]
            [Display(Name = "First Name")]
            public string FirstName { get; set; } = string.Empty;

            [Required, MaxLength(50)]
            [Display(Name = "Last Name")]
            public string LastName { get; set; } = string.Empty;

            [Required, Phone]
            [Display(Name = "Mobile No")]
            public string PhoneNumber { get; set; } = string.Empty;

            [Required, MaxLength(200)]
            [Display(Name = "Billing Address")]
            public string BillingAddress { get; set; } = string.Empty;

            [Required, MaxLength(300)]
            [Display(Name = "Shipping Address")]
            public string ShippingAddress { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Credit Card No")]
            public string CreditCardNo { get; set; } = string.Empty;

            [Required]
            [Display(Name = "Photo (.JPG only)")]
            public IFormFile Photo { get; set; } = default!;
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            ReturnUrl = returnUrl;
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");
            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (!ModelState.IsValid)
                return Page();

            // -----------------------------
            // reCAPTCHA v3 (server-side)
            // -----------------------------
            var minScore = 0.5;
            var minScoreStr = _config["Recaptcha:MinimumScore"];
            if (!string.IsNullOrWhiteSpace(minScoreStr) && double.TryParse(minScoreStr, out var ms))
                minScore = ms;

            var remoteIp = HttpContext.Connection.RemoteIpAddress?.ToString();
            var (ok, score, errors) = await _recaptcha.VerifyAsync(RecaptchaToken, "register", remoteIp);

            if (!ok || score < minScore)
            {
                _logger.LogWarning("reCAPTCHA failed. ok={Ok}, score={Score}, errors={Errors}",
                    ok, score, string.Join(",", errors ?? Array.Empty<string>()));

                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            if (!LooksLikeCardNumber(Input.CreditCardNo))
            {
                ModelState.AddModelError("Input.CreditCardNo", "Invalid credit card number format.");
                return Page();
            }

            if (Input.Photo == null || Input.Photo.Length == 0)
            {
                ModelState.AddModelError("Input.Photo", "Photo is required.");
                return Page();
            }

            var ext = Path.GetExtension(Input.Photo.FileName).ToLowerInvariant();
            if (ext != ".jpg" && ext != ".jpeg")
            {
                ModelState.AddModelError("Input.Photo", "Only .JPG images are allowed.");
                return Page();
            }

            if (!string.Equals(Input.Photo.ContentType, "image/jpeg", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError("Input.Photo", "Invalid image type. Only JPEG is allowed.");
                return Page();
            }

            const long maxBytes = 2 * 1024 * 1024;
            if (Input.Photo.Length > maxBytes)
            {
                ModelState.AddModelError("Input.Photo", "Photo must be 2MB or smaller.");
                return Page();
            }

            if (!await IsJpegAsync(Input.Photo))
            {
                ModelState.AddModelError("Input.Photo", "Invalid JPEG file content.");
                return Page();
            }

            // Save photo to wwwroot/uploads
            var uploadsRoot = Path.Combine(_env.WebRootPath, "uploads");
            Directory.CreateDirectory(uploadsRoot);

            var safeFileName = $"{Guid.NewGuid():N}.jpg";
            var savePath = Path.Combine(uploadsRoot, safeFileName);

            await using (var stream = new FileStream(savePath, FileMode.Create, FileAccess.Write))
            {
                await Input.Photo.CopyToAsync(stream);
            }

            var user = CreateUser();

            await _userStore.SetUserNameAsync(user, Input.Email, CancellationToken.None);
            await _emailStore.SetEmailAsync(user, Input.Email, CancellationToken.None);

            user.FirstName = Input.FirstName.Trim();
            user.LastName = Input.LastName.Trim();
            user.PhoneNumber = Input.PhoneNumber.Trim();
            user.BillingAddress = Input.BillingAddress.Trim();
            user.ShippingAddress = Input.ShippingAddress.Trim();
            user.PhotoFileName = safeFileName;

            // Encrypt CC
            var normalizedCard = new string(Input.CreditCardNo.Where(char.IsDigit).ToArray());
            var (cipher, iv) = _aes.Encrypt(normalizedCard);
            user.EncryptedCreditCard = cipher;
            user.CreditCardIV = iv;

            var result = await _userManager.CreateAsync(user, Input.Password);

            if (!result.Succeeded)
            {
                await _audit.WriteAsync(HttpContext,
                    eventType: "REGISTER_FAIL",
                    userId: null,
                    email: Input.Email,
                    details: string.Join(" | ", result.Errors.Select(e => e.Description)));

                foreach (var error in result.Errors)
                    ModelState.AddModelError(string.Empty, error.Description);

                return Page();
            }

            // Record initial password hash into history + keep only last 2 (centralized)
            await _passwordHistory.RecordAsync(user);

            await _audit.WriteAsync(HttpContext,
                eventType: "REGISTER",
                userId: user.Id,
                email: user.Email,
                details: "User registered successfully.");

            _logger.LogInformation("User created a new account with password.");

            var userIdStr = await _userManager.GetUserIdAsync(user);
            var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
            var callbackUrl = Url.Page(
                "/Account/ConfirmEmail",
                pageHandler: null,
                values: new { area = "Identity", userId = userIdStr, code = code, returnUrl = returnUrl },
                protocol: Request.Scheme);

            await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

            if (_userManager.Options.SignIn.RequireConfirmedAccount)
                return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });

            // Session token for your middleware (single-session policy)
            var token = Guid.NewGuid().ToString("N");
            HttpContext.Session.SetString("AuthToken", token);

            Response.Cookies.Append("AuthToken", token, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Expires = DateTimeOffset.UtcNow.AddMinutes(5)
            });

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

            await _signInManager.SignInAsync(user, isPersistent: false);
            return LocalRedirect(returnUrl);
        }

        private ApplicationUser CreateUser()
        {
            try
            {
                return Activator.CreateInstance<ApplicationUser>();
            }
            catch
            {
                throw new InvalidOperationException($"Can't create an instance of '{nameof(ApplicationUser)}'. " +
                    $"Ensure that '{nameof(ApplicationUser)}' is not an abstract class and has a parameterless constructor, or alternatively " +
                    $"override the register page in /Areas/Identity/Pages/Account/Register.cshtml");
            }
        }

        private IUserEmailStore<ApplicationUser> GetEmailStore()
        {
            if (!_userManager.SupportsUserEmail)
                throw new NotSupportedException("The default UI requires a user store with email support.");

            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}
