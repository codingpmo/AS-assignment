using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;
using AceJobAgency.Services;
using System.Text.Json;

namespace AceJobAgency.Pages
{
    public class Setup2FAModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly TwoFactorService _twoFactorService;

        public Setup2FAModel(AuthDbContext context, TwoFactorService twoFactorService)
        {
            _context = context;
            _twoFactorService = twoFactorService;
        }

        [BindProperty]
        public Setup2FAInputModel Input { get; set; }

        public string QrCodeUrl { get; set; }
        public string Secret { get; set; }
        public List<string> BackupCodes { get; set; }
        public string SuccessMessage { get; set; }
        public bool ShowQrCode { get; set; }
        public bool ShowVerification { get; set; }

        public class Setup2FAInputModel
        {
            [Required]
            [Display(Name = "6-Digit Code")]
            [StringLength(6, MinimumLength = 6)]
            public string VerificationCode { get; set; }
        }

        public async Task<IActionResult> OnGetAsync()
        {
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

            // Generate new secret and store in TempData
            Secret = _twoFactorService.GenerateTwoFactorSecret();
            TempData["TwoFactorSecret"] = Secret;
            QrCodeUrl = _twoFactorService.GenerateQrCodeUrl(Secret, user.Email);
            ShowQrCode = true;

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

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

            // Get the secret from session (user should have scanned the QR code)
            var secret = TempData["TwoFactorSecret"] as string;
            if (string.IsNullOrEmpty(secret))
            {
                ModelState.AddModelError(string.Empty, "Session expired. Please try again.");
                return Page();
            }

            // Verify the code
            if (!_twoFactorService.VerifyTwoFactorCode(secret, Input.VerificationCode))
            {
                ModelState.AddModelError("Input.VerificationCode", "Invalid verification code. Please try again.");
                ShowVerification = true;
                return Page();
            }

            // Generate backup codes
            var backupCodes = _twoFactorService.GenerateBackupCodes();

            // Enable 2FA for user
            user.IsTwoFactorEnabled = true;
            user.TwoFactorSecret = secret;
            user.TwoFactorSetupDate = DateTime.Now;
            user.BackupCodes = backupCodes;

            // Log the activity
            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "Two-Factor Authentication Enabled",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);

            await _context.SaveChangesAsync();

            BackupCodes = backupCodes;
            SuccessMessage = "Two-Factor Authentication has been enabled successfully. Please save your backup codes in a secure location.";

            return Page();
        }

        public IActionResult OnPostSetSecret()
        {
            var secret = _twoFactorService.GenerateTwoFactorSecret();
            var userEmail = HttpContext.Session.GetString("UserEmail");
            
            if (!string.IsNullOrEmpty(userEmail))
            {
                var user = _context.Users.FirstOrDefault(u => u.Email == userEmail);
                if (user != null)
                {
                    var qrUrl = _twoFactorService.GenerateQrCodeUrl(secret, user.Email);
                    TempData["TwoFactorSecret"] = secret;
                    
                    return new JsonResult(new { 
                        secret = secret, 
                        qrCodeUrl = qrUrl 
                    });
                }
            }

            return BadRequest();
        }
    }
}
