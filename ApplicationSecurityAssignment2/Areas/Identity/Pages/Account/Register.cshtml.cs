// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System.IO;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using ApplicationSecurityAssignment2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Http;


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


        public RegisterModel(
            UserManager<ApplicationUser> userManager,
            IUserStore<ApplicationUser> userStore,
            SignInManager<ApplicationUser> signInManager,
            ILogger<RegisterModel> logger,
            IEmailSender emailSender,
            AesEncryptionService aes,
            AuditLogService audit)
        {
            _userManager = userManager;
            _userStore = userStore;
            _emailStore = GetEmailStore();
            _signInManager = signInManager;
            _logger = logger;
            _emailSender = emailSender;
            _aes = aes;
            _audit = audit;
        }
        private static bool LooksLikeCardNumber(string input)
        {
            // allow digits + spaces/hyphens, then check length after stripping
            var digits = new string(input.Where(char.IsDigit).ToArray());
            return digits.Length is >= 12 and <= 19;
        }

        private static async Task<bool> IsJpegAsync(IFormFile file)
        {
            // JPEG starts with FF D8 and ends with FF D9 (we check header only, good enough)
            if (file.Length < 2) return false;

            using var stream = file.OpenReadStream();
            var header = new byte[2];
            var read = await stream.ReadAsync(header, 0, 2);
            return read == 2 && header[0] == 0xFF && header[1] == 0xD8;
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
        public string ReturnUrl { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        /// <summary>
        ///     This API supports the ASP.NET Core Identity default UI infrastructure and is not intended to be used
        ///     directly from your code. This API may change or be removed in future releases.
        /// </summary>
        public class InputModel
        {
         
            [Required]
            [EmailAddress]
            [Display(Name = "Email")]
            public string Email { get; set; }

            [Required]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{12,}$", ErrorMessage = "Password must be at least 12 characters and include upper, lower, number, and special character.")]
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
            if (ModelState.IsValid)
            {
                // Extra server-side checks
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

                // JPG only (by content type + extension). Content-type can be spoofed, so we also check signature later if you want.
                var allowedContentTypes = new[] { "image/jpeg" };
                var ext = Path.GetExtension(Input.Photo.FileName).ToLowerInvariant();

                if (ext != ".jpg" && ext != ".jpeg")
                {
                    ModelState.AddModelError("Input.Photo", "Only .JPG images are allowed.");
                    return Page();
                }

                if (!allowedContentTypes.Contains(Input.Photo.ContentType))
                {
                    ModelState.AddModelError("Input.Photo", "Invalid image type. Only JPEG is allowed.");
                    return Page();
                }

                // size limit (pick something safe for demo)
                const long maxBytes = 2 * 1024 * 1024; // 2MB
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


                // Save photo with safe server-generated filename
                var uploadsRoot = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot", "uploads");
                Directory.CreateDirectory(uploadsRoot);

                var safeFileName = $"{Guid.NewGuid():N}.jpg";
                var savePath = Path.Combine(uploadsRoot, safeFileName);

                using (var stream = new FileStream(savePath, FileMode.CreateNew))
                {
                    await Input.Photo.CopyToAsync(stream);
                }


                var user = CreateUser();

                // Identity built-in fields
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

                if (result.Succeeded)
                {
                    await _audit.WriteAsync(HttpContext,
                    eventType: "REGISTER",
                    userId: user.Id,
                    email: user.Email,
                    details: "User registered successfully.");

                    _logger.LogInformation("User created a new account with password.");

                    var userId = await _userManager.GetUserIdAsync(user);
                    var code = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                    code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                    var callbackUrl = Url.Page(
                        "/Account/ConfirmEmail",
                        pageHandler: null,
                        values: new { area = "Identity", userId = userId, code = code, returnUrl = returnUrl },
                        protocol: Request.Scheme);

                    await _emailSender.SendEmailAsync(Input.Email, "Confirm your email",
                        $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUrl)}'>clicking here</a>.");

                    if (_userManager.Options.SignIn.RequireConfirmedAccount)
                    {
                        return RedirectToPage("RegisterConfirmation", new { email = Input.Email, returnUrl = returnUrl });
                    }
                    else
                    {
                        await _signInManager.SignInAsync(user, isPersistent: false);
                        return LocalRedirect(returnUrl);
                    }
                }

                await _audit.WriteAsync(HttpContext,
                    eventType: "REGISTER_FAIL",
                    userId: null,
                    email: Input.Email,
                    details: string.Join(" | ", result.Errors.Select(e => e.Description)));

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                    
                    ;
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
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
            {
                throw new NotSupportedException("The default UI requires a user store with email support.");
            }
            return (IUserEmailStore<ApplicationUser>)_userStore;
        }
    }
}
