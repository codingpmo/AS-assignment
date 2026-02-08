using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using AceJobAgency.Models;

namespace AceJobAgency.Pages
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly AuthDbContext _context;

        public ForgotPasswordModel(AuthDbContext context)
        {
            _context = context;
        }

        [BindProperty]
        public ForgotPasswordInputModel Input { get; set; }

        public string SuccessMessage { get; set; }
        public string InfoMessage { get; set; }

        public class ForgotPasswordInputModel
        {
            [Required]
            [EmailAddress]
            [Display(Name = "Email Address")]
            public string Email { get; set; }
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

            var user = _context.Users.FirstOrDefault(u => u.Email == Input.Email);

            if (user == null)
            {
                // For security reasons, don't reveal if email exists
                InfoMessage = "If an account with that email exists, a password reset link will be sent.";
                return Page();
            }

            // Generate a reset token (in a real application, this would be a secure token stored in the database)
            string resetToken = Guid.NewGuid().ToString();
            
            // For this demo, we'll store it in session with a 15-minute expiry
            HttpContext.Session.SetString($"PasswordResetToken_{user.Id}", resetToken);
            HttpContext.Session.SetString($"PasswordResetExpiry_{user.Id}", DateTime.Now.AddMinutes(15).ToString());

            // In a production system, you would send an email with:
            // Reset Link: https://yoursite.com/reset-password?token={resetToken}&email={userEmail}
            // But for this assignment, we'll simulate it by showing the reset link
            
            InfoMessage = $"Password reset link has been generated. For demo purposes: <a href='/ResetPassword?token={resetToken}&userId={user.Id}' class='btn btn-primary btn-sm'>Click here to reset password</a>";
            SuccessMessage = "A password reset link has been sent to your email address.";

            // Log the activity
            var auditLog = new AuditLog
            {
                UserId = user.Email,
                Activity = "Forgot Password Request",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);
            await _context.SaveChangesAsync();

            return Page();
        }
    }
}
