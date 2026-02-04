using ApplicationSecurityAssignment2.Data;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

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

            // ---- Allow these paths without AuthToken enforcement ----
            if (IsBypassedPath(path))
            {
                await _next(context);
                return;
            }

            // Only enforce for authenticated users
            if (context.User?.Identity?.IsAuthenticated == true)
            {
                var sessionToken = context.Session.GetString("AuthToken");
                context.Request.Cookies.TryGetValue("AuthToken", out var cookieToken);

                // Must exist + match
                if (string.IsNullOrWhiteSpace(sessionToken) ||
                    string.IsNullOrWhiteSpace(cookieToken) ||
                    !string.Equals(sessionToken, cookieToken, StringComparison.Ordinal))
                {
                    await ForceLogout(context);
                    return;
                }

                var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (string.IsNullOrWhiteSpace(userId))
                {
                    await ForceLogout(context);
                    return;
                }

                // Must match latest active non-revoked session
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

        private static bool IsBypassedPath(string path)
        {
            // Error pages
            if (path.StartsWith("/Error", StringComparison.OrdinalIgnoreCase))
                return true;

            // Identity pages (login/register/logout/forgot/reset/etc.)
            if (path.StartsWith("/Identity", StringComparison.OrdinalIgnoreCase))
                return true;

            // Static files + uploads
            if (path.StartsWith("/css", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/js", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/lib", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/favicon", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/uploads", StringComparison.OrdinalIgnoreCase) ||
                path.StartsWith("/_framework", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        private static async Task ForceLogout(HttpContext context)
        {
            // Clear auth + session + cookies
            await context.SignOutAsync();
            context.Session.Clear();

            context.Response.Cookies.Delete("AuthToken");
            context.Response.Cookies.Delete(".AspNetCore.Session");

            // Avoid redirect loops + don't redirect if response already started
            var path = context.Request.Path.Value ?? "";
            if (!context.Response.HasStarted &&
                !path.StartsWith("/Identity/Account/Login", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.Redirect("/Identity/Account/Login");
            }
        }
    }
}
