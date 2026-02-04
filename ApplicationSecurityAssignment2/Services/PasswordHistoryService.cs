// Services/PasswordHistoryService.cs
using ApplicationSecurityAssignment2.Data;
using ApplicationSecurityAssignment2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace ApplicationSecurityAssignment2.Services
{
    public class PasswordHistoryService
    {
        private readonly ApplicationDbContext _db;
        private readonly IPasswordHasher<ApplicationUser> _hasher;

        public PasswordHistoryService(ApplicationDbContext db, IPasswordHasher<ApplicationUser> hasher)
        {
            _db = db;
            _hasher = hasher;
        }

        // Returns true if newPassword matches any of last N password hashes
        public async Task<bool> IsInRecentHistoryAsync(ApplicationUser user, string newPassword, int lastN = 2)
        {
            if (user == null) return false;

            var recent = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.ChangedAtUtc)
                .Take(lastN)
                .Select(p => p.PasswordHash)
                .ToListAsync();

            foreach (var oldHash in recent)
            {
                var verify = _hasher.VerifyHashedPassword(user, oldHash, newPassword);
                if (verify == PasswordVerificationResult.Success ||
                    verify == PasswordVerificationResult.SuccessRehashNeeded)
                {
                    return true;
                }
            }

            return false;
        }

        // used for password minimum/maximum age checks
        public async Task<DateTime?> GetLastChangedUtcAsync(string userId)
        {
            if (string.IsNullOrWhiteSpace(userId))
                return null;

            return await _db.PasswordHistories
                .Where(p => p.UserId == userId)
                .OrderByDescending(p => p.ChangedAtUtc)
                .Select(p => (DateTime?)p.ChangedAtUtc)
                .FirstOrDefaultAsync();
        }

        public async Task RecordAsync(ApplicationUser user)
        {
            // user.PasswordHash is already the latest hash after successful change/reset/create
            if (string.IsNullOrWhiteSpace(user?.Id) || string.IsNullOrWhiteSpace(user.PasswordHash))
                return;

            _db.PasswordHistories.Add(new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash,
                ChangedAtUtc = DateTime.UtcNow
            });

            // keep only last 2
            var extra = await _db.PasswordHistories
                .Where(p => p.UserId == user.Id)
                .OrderByDescending(p => p.ChangedAtUtc)
                .Skip(2)
                .ToListAsync();

            if (extra.Count > 0)
                _db.PasswordHistories.RemoveRange(extra);

            await _db.SaveChangesAsync();
        }
    }
}
