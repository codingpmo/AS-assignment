using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class ResetPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly PasswordSecurityService _passwordSecurityService;

        public ResetPasswordModel(AuthDbContext context, PasswordSecurityService passwordSecurityService)
        {
            _context = context;
            _passwordSecurityService = passwordSecurityService;
        }

        [BindProperty]
        public ResetPasswordInputModel Input { get; set; }

        [BindProperty(SupportsGet = true)]
        public string Token { get; set; }

        [BindProperty(SupportsGet = true)]
        public int UserId { get; set; }

        public string SuccessMessage { get; set; }

        public class ResetPasswordInputModel
        {
            [Required]
            [DataType(DataType.Password)]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("NewPassword", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public void OnGet()
        {
            // Validate token
            if (string.IsNullOrEmpty(Token) || UserId == 0)
            {
                ModelState.AddModelError(string.Empty, "Invalid reset link.");
            }
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Validate token
            if (string.IsNullOrEmpty(Token) || UserId == 0)
            {
                ModelState.AddModelError(string.Empty, "Invalid reset link.");
                return Page();
            }

            var user = _context.Users.FirstOrDefault(u => u.Id == UserId);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return Page();
            }

            // Check if token exists and is still valid
            var tokenKey = $"PasswordResetToken_{user.Id}";
            var expiryKey = $"PasswordResetExpiry_{user.Id}";
            
            var storedToken = HttpContext.Session.GetString(tokenKey);
            var expiryStr = HttpContext.Session.GetString(expiryKey);

            if (storedToken != Token)
            {
                ModelState.AddModelError(string.Empty, "Invalid or expired reset link.");
                return Page();
            }

            if (!DateTime.TryParse(expiryStr, out var expiry) || DateTime.Now > expiry)
            {
                ModelState.AddModelError(string.Empty, "The reset link has expired. Please request a new one.");
                return Page();
            }

            // Validate password complexity
            if (!ValidatePasswordComplexity(Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword", "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
                return Page();
            }

            // Check if new password matches current or previous passwords
            if (_passwordSecurityService.IsPasswordInHistory(user, Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword", "You cannot reuse your current or recent passwords.");
                return Page();
            }

            // Ensure HasCompletedFirstPasswordChange is set so this counts as a real password change
            user.HasCompletedFirstPasswordChange = true;

            // Update password
            await _passwordSecurityService.UpdatePasswordAsync(user, Input.NewPassword);

            // Reload user from database to get updated values
            user = _context.Users.FirstOrDefault(u => u.Id == UserId);

            // Clear the reset token
            HttpContext.Session.Remove(tokenKey);
            HttpContext.Session.Remove(expiryKey);

            // Log the activity
            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "Password Reset",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();

            SuccessMessage = "Your password has been reset successfully. You can now log in with your new password.";
            return Page();
        }

        private bool ValidatePasswordComplexity(string password)
        {
            if (string.IsNullOrEmpty(password) || password.Length < 12)
                return false;

            bool hasUppercase = password.Any(c => char.IsUpper(c));
            bool hasLowercase = password.Any(c => char.IsLower(c));
            bool hasDigit = password.Any(c => char.IsDigit(c));
            bool hasSpecialChar = password.Any(c => !char.IsLetterOrDigit(c));

            return hasUppercase && hasLowercase && hasDigit && hasSpecialChar;
        }
    }
}
