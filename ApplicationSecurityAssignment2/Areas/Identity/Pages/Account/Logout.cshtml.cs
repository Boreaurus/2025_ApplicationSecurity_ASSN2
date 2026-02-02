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
using ApplicationSecurityAssignment2.Data;

namespace ApplicationSecurityAssignment2.Areas.Identity.Pages.Account
{
    [AllowAnonymous] //Allow all users to access logout
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly ILogger<LogoutModel> _logger;
        private readonly AuditLogService _audit;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _db;

        public LogoutModel(
            SignInManager<ApplicationUser> signInManager, 
            ILogger<LogoutModel> logger,
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

        public async Task<IActionResult> OnPost(string returnUrl = null)
        {
            var user = await _userManager.GetUserAsync(User);

            await _signInManager.SignOutAsync();

            HttpContext.Session.Clear();
            Response.Cookies.Delete("AuthToken");
            Response.Cookies.Delete(".AspNetCore.Session");

            if (user != null)
            {
                var sessions = _db.ActiveSessions.Where(s => s.UserId == user.Id && !s.IsRevoked);
                foreach (var s in sessions) s.IsRevoked = true;
                await _db.SaveChangesAsync();
            }


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
