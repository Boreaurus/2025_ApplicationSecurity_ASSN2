using ApplicationSecurityAssignment2.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace ApplicationSecurityAssignment2.Middleware
{
    public class AuthTokenMiddleware
    {
        private readonly RequestDelegate _next;

        public AuthTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, ApplicationDbContext db)
        {
            var path = context.Request.Path.Value ?? "";
            if (path.StartsWith("/Identity/Account/Login", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/Identity/Account/Register", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/Identity/Account/Logout", StringComparison.OrdinalIgnoreCase))
            {
                await _next(context);
                return;
            }
            // Only enforce for authenticated users
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var sessionToken = context.Session.GetString("AuthToken");
                context.Request.Cookies.TryGetValue("AuthToken", out var cookieToken);

                // session token must match cookie token 
                if (string.IsNullOrWhiteSpace(sessionToken) ||
                    string.IsNullOrWhiteSpace(cookieToken) ||
                    !string.Equals(sessionToken, cookieToken, StringComparison.Ordinal))
                {
                    await ForceLogout(context);
                    return;
                }

                var userId = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;

                if (string.IsNullOrWhiteSpace(userId))
                {
                    await ForceLogout(context);
                    return;
                }

                // Multi-login detection: token must match latest non-revoked DB token 
                var active = await db.ActiveSessions
                    .Where(s => s.UserId == userId && !s.IsRevoked && s.ExpiresAtUtc > DateTime.UtcNow)
                    .OrderByDescending(s => s.IssuedAtUtc)
                    .FirstOrDefaultAsync();

                if (active == null || !string.Equals(active.SessionToken, sessionToken, StringComparison.Ordinal))
                {
                    await ForceLogout(context);
                    return;
                }
            }

            await _next(context);
        }

        private static async Task ForceLogout(HttpContext context)
        {
            // clear auth + session + cookies
            await context.SignOutAsync();
            context.Session.Clear();

            context.Response.Cookies.Delete("AuthToken");
            context.Response.Cookies.Delete(".AspNetCore.Session");

            context.Response.Redirect("/Identity/Account/Login");
        }
    }
}
