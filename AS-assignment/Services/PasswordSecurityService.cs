using AceJobAgency.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Services
{
    public class PasswordSecurityService
    {
        private readonly AuthDbContext _context;
        private const int PasswordHistoryCount = 2; // Prevent reusing last 2 passwords
        private const int MinPasswordAgeDays = 1; // Minimum days before password can be changed
        private const int MaxPasswordAgeDays = 90; // Maximum days before password must be changed

        public PasswordSecurityService(AuthDbContext context)
        {
            _context = context;
        }

        /// <summary>
        /// Checks if a password has been used in the user's password history.
        /// </summary>
        public bool IsPasswordInHistory(ApplicationUser user, string newPassword)
        {
            var passwordHasher = new PasswordHasher<ApplicationUser>();
            
            // Check current password
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, newPassword);
            if (result == PasswordVerificationResult.Success)
            {
                return true;
            }

            // Check previous passwords
            if (!string.IsNullOrEmpty(user.PreviousPasswordHash1))
            {
                result = passwordHasher.VerifyHashedPassword(user, user.PreviousPasswordHash1, newPassword);
                if (result == PasswordVerificationResult.Success)
                {
                    return true;
                }
            }

            if (!string.IsNullOrEmpty(user.PreviousPasswordHash2))
            {
                result = passwordHasher.VerifyHashedPassword(user, user.PreviousPasswordHash2, newPassword);
                if (result == PasswordVerificationResult.Success)
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Checks if the user can change their password based on minimum password age policy.
        /// First password change after registration is always allowed.
        /// </summary>
        public bool CanChangePassword(ApplicationUser user)
        {
            // Allow first password change immediately after registration
            if (!user.HasCompletedFirstPasswordChange)
            {
                return true;
            }

            // After first change, enforce minimum password age policy
            var daysSinceLastChange = (DateTime.Now - user.LastPasswordChangedDate).TotalDays;
            return daysSinceLastChange >= user.MinimumPasswordAgeDays;
        }

        /// <summary>
        /// Checks if the user must change their password based on maximum password age policy.
        /// </summary>
        public bool MustChangePassword(ApplicationUser user)
        {
            var daysSinceLastChange = (DateTime.Now - user.LastPasswordChangedDate).TotalDays;
            return daysSinceLastChange >= user.MaximumPasswordAgeDays;
        }

        /// <summary>
        /// Gets the number of days until the password expires.
        /// </summary>
        public int GetDaysUntilPasswordExpiry(ApplicationUser user)
        {
            var daysSinceLastChange = (int)(DateTime.Now - user.LastPasswordChangedDate).TotalDays;
            var daysUntilExpiry = user.MaximumPasswordAgeDays - daysSinceLastChange;
            return Math.Max(0, daysUntilExpiry);
        }

        /// <summary>
        /// Stores the password in history and updates the user's password.
        /// </summary>
        public async Task UpdatePasswordAsync(ApplicationUser user, string newPassword)
        {
            var passwordHasher = new PasswordHasher<ApplicationUser>();

            // Shift old passwords down the history
            user.PreviousPasswordHash2 = user.PreviousPasswordHash1;
            user.PreviousPasswordHash1 = user.PasswordHash;
            user.PasswordHash = passwordHasher.HashPassword(user, newPassword);
            user.LastPasswordChangedDate = DateTime.Now;

            // Mark that first password change has been completed
            if (!user.HasCompletedFirstPasswordChange)
            {
                user.HasCompletedFirstPasswordChange = true;
            }

            // Update the user entity
            _context.Users.Update(user);

            // Add to password history table
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash,
                ChangedDate = DateTime.Now
            };
            _context.PasswordHistories.Add(passwordHistory);

            await _context.SaveChangesAsync();
        }

        /// <summary>
        /// Gets the days remaining before password change is allowed.
        /// </summary>
        public int GetDaysBeforePasswordChangeAllowed(ApplicationUser user)
        {
            var daysSinceLastChange = (int)(DateTime.Now - user.LastPasswordChangedDate).TotalDays;
            var daysToWait = user.MinimumPasswordAgeDays - daysSinceLastChange;
            return Math.Max(0, daysToWait);
        }
    }
}
