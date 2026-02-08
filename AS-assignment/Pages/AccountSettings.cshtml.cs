using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class AccountSettingsModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly PasswordSecurityService _passwordSecurityService;

        public AccountSettingsModel(AuthDbContext context, PasswordSecurityService passwordSecurityService)
        {
            _context = context;
            _passwordSecurityService = passwordSecurityService;
        }

        public ApplicationUser User { get; set; }
        public int DaysUntilPasswordExpiry { get; set; }
        public bool MustChangePassword { get; set; }
        public string SuccessMessage { get; set; }

        public IActionResult OnGet()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }

            User = _context.Users.FirstOrDefault(u => u.Email == userEmail);
            if (User == null)
            {
                return RedirectToPage("/Login");
            }

            DaysUntilPasswordExpiry = _passwordSecurityService.GetDaysUntilPasswordExpiry(User);
            MustChangePassword = _passwordSecurityService.MustChangePassword(User);

            return Page();
        }

        public async Task<IActionResult> OnPostDisable2FAAsync()
        {
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }

            User = _context.Users.FirstOrDefault(u => u.Email == userEmail);
            if (User == null)
            {
                return RedirectToPage("/Login");
            }

            User.IsTwoFactorEnabled = false;
            User.TwoFactorSecret = null;
            User.BackupCodes = null;

            var auditLog = new AuditLog
            {
                UserId = User.Email,
                Activity = "Two-Factor Authentication Disabled",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);

            await _context.SaveChangesAsync();

            SuccessMessage = "Two-Factor Authentication has been disabled.";
            return RedirectToPage();
        }

        public IActionResult OnPostSetup2FAAsync()
        {
            return RedirectToPage("/Setup2FA");
        }

        public IActionResult OnPostChangePasswordAsync()
        {
            return RedirectToPage("/ChangePassword");
        }
    }
}
