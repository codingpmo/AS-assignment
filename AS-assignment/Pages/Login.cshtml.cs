using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class LoginModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly PasswordSecurityService _passwordSecurityService;
        private readonly RecaptchaService _recaptchaService;
        private readonly IConfiguration _configuration;

        public LoginModel(AuthDbContext context, IHttpContextAccessor httpContextAccessor, 
            PasswordSecurityService passwordSecurityService, RecaptchaService recaptchaService,
            IConfiguration configuration)
        {
            _context = context;
            _httpContextAccessor = httpContextAccessor;
            _passwordSecurityService = passwordSecurityService;
            _recaptchaService = recaptchaService;
            _configuration = configuration;
        }

        [BindProperty]
        public LoginInputModel Input { get; set; }

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public string SiteKey { get; set; }

        public class LoginInputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }
        }

        public void OnGet()
        {
            SiteKey = _configuration["RecaptchaSettings:SiteKey"];
            
            // Log for debugging
            if (string.IsNullOrEmpty(SiteKey))
            {
                Console.WriteLine("WARNING: SiteKey is null or empty in OnGet");
            }
            
            RecaptchaToken = null;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            SiteKey = _configuration["RecaptchaSettings:SiteKey"];

            if (!ModelState.IsValid) 
                return Page();

            // Verify reCAPTCHA token - MUST PASS
            if (string.IsNullOrEmpty(RecaptchaToken))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            bool isCaptchaValid = await _recaptchaService.VerifyTokenAsync(RecaptchaToken);
            if (!isCaptchaValid)
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA verification failed. Please try again.");
                return Page();
            }

            var user = _context.Users.FirstOrDefault(u => u.Email == Input.Email);

            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                return Page();
            }

            // Check if account is locked and if lockout period has expired
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value > DateTime.Now)
            {
                var minutesRemaining = Math.Ceiling((user.LockoutEnd.Value - DateTime.Now).TotalMinutes);
                ModelState.AddModelError(string.Empty, $"Account is locked. Please try again in {minutesRemaining} minute(s).");
                return Page();
            }

            // Unlock account if lockout period has expired
            if (user.LockoutEnd.HasValue && user.LockoutEnd.Value <= DateTime.Now)
            {
                user.LockoutEnd = null;
                user.FailedLoginAttempts = 0;
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
            }

            var passwordHasher = new PasswordHasher<ApplicationUser>();
            var result = passwordHasher.VerifyHashedPassword(user, user.PasswordHash, Input.Password);

            if (result == PasswordVerificationResult.Failed)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= 3)
                {
                    user.LockoutEnd = DateTime.Now.AddMinutes(10);
                    ModelState.AddModelError(string.Empty, "Account locked due to multiple failed attempts.");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                }

                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                return Page();
            }

            if (_passwordSecurityService.MustChangePassword(user))
            {
                user.FailedLoginAttempts = 0;
                user.LockoutEnd = null;
                _context.Users.Update(user);
                await _context.SaveChangesAsync();

                HttpContext.Session.SetString("UserEmailForPasswordChange", user.Email);
                return RedirectToPage("/ChangePassword");
            }

            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;

            if (user.IsTwoFactorEnabled)
            {
                HttpContext.Session.SetString("UserEmailForTwoFactor", user.Email);
                HttpContext.Session.SetInt32("UserIdForTwoFactor", user.Id);
                HttpContext.Session.SetString("TwoFactorAttemptTime", DateTime.Now.AddMinutes(5).ToString());
                
                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                return RedirectToPage("/Verify2FA");
            }

            string sessionGuid = Guid.NewGuid().ToString();
            user.SessionId = sessionGuid;

            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "User Logged In",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            HttpContext.Session.SetString("UserEmail", user.Email);
            HttpContext.Session.SetString("AuthToken", sessionGuid);

            return RedirectToPage("/Index");
        }
    }
}