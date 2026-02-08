using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class Verify2FAModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly TwoFactorService _twoFactorService;

        public Verify2FAModel(AuthDbContext context, TwoFactorService twoFactorService)
        {
            _context = context;
            _twoFactorService = twoFactorService;
        }

        [BindProperty]
        public Verify2FAInputModel Input { get; set; }

        public bool UseBackupCode { get; set; }
        public string ErrorMessage { get; set; }

        public class Verify2FAInputModel
        {
            [Required]
            [Display(Name = "6-Digit Code or Backup Code")]
            public string Code { get; set; }
        }

        public IActionResult OnGet()
        {
            var userEmailForTwoFactor = HttpContext.Session.GetString("UserEmailForTwoFactor");
            if (string.IsNullOrEmpty(userEmailForTwoFactor))
            {
                return RedirectToPage("/Login");
            }

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var userEmailForTwoFactor = HttpContext.Session.GetString("UserEmailForTwoFactor");
            var userIdForTwoFactor = HttpContext.Session.GetInt32("UserIdForTwoFactor");
            var attemptTimeStr = HttpContext.Session.GetString("TwoFactorAttemptTime");

            if (string.IsNullOrEmpty(userEmailForTwoFactor) || !userIdForTwoFactor.HasValue)
            {
                ErrorMessage = "Session expired. Please log in again.";
                return RedirectToPage("/Login");
            }

            // Check if attempt has expired (5 minutes)
            if (DateTime.TryParse(attemptTimeStr, out var attemptTime) && DateTime.Now > attemptTime)
            {
                ErrorMessage = "2FA verification timed out. Please log in again.";
                return RedirectToPage("/Login");
            }

            var user = _context.Users.FirstOrDefault(u => u.Id == userIdForTwoFactor.Value && u.Email == userEmailForTwoFactor);
            if (user == null || !user.IsTwoFactorEnabled)
            {
                return RedirectToPage("/Login");
            }

            // Try to verify as TOTP code first
            bool isValid = _twoFactorService.VerifyTwoFactorCode(user.TwoFactorSecret, Input.Code);

            // If not valid, try backup code
            if (!isValid && user.BackupCodes != null && user.BackupCodes.Count > 0)
            {
                isValid = _twoFactorService.VerifyAndRemoveBackupCode(user, Input.Code);
                if (isValid)
                {
                    // Save the updated backup codes
                    await _context.SaveChangesAsync();
                }
            }

            if (!isValid)
            {
                ModelState.AddModelError("Input.Code", "Invalid code. Please try again.");
                return Page();
            }

            // 2FA verification successful
            var passwordSecurityService = new PasswordSecurityService(_context);

            // Generate Session ID
            string sessionGuid = Guid.NewGuid().ToString();
            user.SessionId = sessionGuid;

            // Save Audit Log
            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "User Logged In (2FA Verified)",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();

            // Clear 2FA session data
            HttpContext.Session.Remove("UserEmailForTwoFactor");
            HttpContext.Session.Remove("UserIdForTwoFactor");
            HttpContext.Session.Remove("TwoFactorAttemptTime");

            // Set authenticated session
            HttpContext.Session.SetString("UserEmail", user.Email);
            HttpContext.Session.SetString("AuthToken", sessionGuid);

            return RedirectToPage("/Index");
        }
    }
}
