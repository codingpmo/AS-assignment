using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class ChangePasswordModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly PasswordSecurityService _passwordSecurityService;

        public ChangePasswordModel(AuthDbContext context, PasswordSecurityService passwordSecurityService)
        {
            _context = context;
            _passwordSecurityService = passwordSecurityService;
        }

        [BindProperty]
        public ChangePasswordInputModel Input { get; set; }

        public string SuccessMessage { get; set; }
        public int MinimumPasswordAgeDays { get; set; } = 1;
        public int MaximumPasswordAgeDays { get; set; } = 90;

        public class ChangePasswordInputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current Password")]
            public string CurrentPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "New Password")]
            public string NewPassword { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Confirm New Password")]
            [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            // Get logged-in user
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }

            var user = _context.Users.FirstOrDefault(u => u.Email == userEmail);
            if (user == null)
            {
                return RedirectToPage("/Login");
            }

            // Check if user can change password (minimum age enforcement)
            if (!_passwordSecurityService.CanChangePassword(user))
            {
                var daysToWait = _passwordSecurityService.GetDaysBeforePasswordChangeAllowed(user);
                ModelState.AddModelError(string.Empty, $"You cannot change your password yet. Please wait {daysToWait} more day(s).");
                return Page();
            }

            // Verify current password
            var passwordHasher = new PasswordHasher<ApplicationUser>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, Input.CurrentPassword);

            if (result == PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError("Input.CurrentPassword", "Current password is incorrect.");
                return Page();
            }

            // Validate password complexity
            if (!ValidatePasswordComplexity(Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword", "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.");
                return Page();
            }

            // Check if new password matches current or previous passwords (password history)
            if (_passwordSecurityService.IsPasswordInHistory(user, Input.NewPassword))
            {
                ModelState.AddModelError("Input.NewPassword", "You cannot reuse your current or recent passwords. Please choose a different password.");
                return Page();
            }

            // Update password
            await _passwordSecurityService.UpdatePasswordAsync(user, Input.NewPassword);

            // Log the activity
            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "Password Changed",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();

            SuccessMessage = "Your password has been changed successfully.";
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
