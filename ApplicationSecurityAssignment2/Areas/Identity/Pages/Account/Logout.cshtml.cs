// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
#nullable disable

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using ApplicationSecurityAssignment2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using ApplicationSecurityAssignment2.Services;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly AuditLogService _audit;
        private readonly UserManager<ApplicationUser> _userManager;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager, 
            ILogger<LogoutModel> logger,
            UserManager<ApplicationUser> userManager,
            AuditLogService audit)
        {
            _signInManager = signInManager;
            _logger = logger;
            _userManager = userManager;
            _audit = audit;
        }

        public async Task<IActionResult> OnPost(string returnUrl = null)
        {
            var user = await _userManager.GetUserAsync(User);

            await _signInManager.SignOutAsync();

            await _audit.WriteAsync(HttpContext,
                eventType: "LOGOUT",
                userId: user?.Id,
                email: user?.Email,
                details: "User logged out.");

            _logger.LogInformation("User logged out.");
            if (returnUrl != null)
            {
                return LocalRedirect(returnUrl);
            }
            else
            {
                // This needs to be a redirect so that the browser performs a new
                // request and the identity for the user gets updated.
                return RedirectToPage("/Account/Login");
            }
        }
    }
}
