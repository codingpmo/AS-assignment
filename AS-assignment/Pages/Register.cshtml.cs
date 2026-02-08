using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using System.Text.Encodings.Web;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly EncryptionService _encryptionService;
        private readonly IWebHostEnvironment _environment;

        public RegisterModel(AuthDbContext context, EncryptionService encryptionService, IWebHostEnvironment environment)
        {
            _context = context;
            _encryptionService = encryptionService;
            _environment = environment;
        }

        [BindProperty]
        public RegisterInputModel Input { get; set; }

        // This class defines the form fields. 
        // It must be INSIDE RegisterModel but OUTSIDE any methods like OnPostAsync.
        public class RegisterInputModel
        {
            [Required]
            public string FirstName { get; set; }

            [Required]
            public string LastName { get; set; }

            [Required]
            public string Gender { get; set; }

            [Required]
            public string NRIC { get; set; }

            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).{12,}$",
                ErrorMessage = "Password must be at least 12 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.")]
            public string Password { get; set; }

            [Required]
            [DataType(DataType.Password)]
            [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
            public string ConfirmPassword { get; set; }

            [Required]
            [DataType(DataType.Date)]
            public DateTime DateOfBirth { get; set; }

            [Required]
            public IFormFile Resume { get; set; }

            [Required]
            public string WhoAmI { get; set; }
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

            // 1. Check for Duplicate Email
            // Note: If '_context.Users' is red, ensure your AuthDbContext class has 'public DbSet<ApplicationUser> Users { get; set; }'
                   
            if (_context.Users.Any(u => u.Email == Input.Email))
            {
                ModelState.AddModelError("Input.Email", "Email address is already in use.");
                return Page();
            }

            // 2. File Upload Validation (.pdf or .docx only)
            var allowedExtensions = new[] { ".pdf", ".docx" };
            var fileExtension = Path.GetExtension(Input.Resume.FileName).ToLower();
            if (!allowedExtensions.Contains(fileExtension))
            {
                ModelState.AddModelError("Input.Resume", "Only .pdf and .docx files are allowed.");
                return Page();
            }

            // 2a. File Size Validation (5MB limit)
            const long maxFileSize = 5 * 1024 * 1024; // 5MB
            if (Input.Resume.Length > maxFileSize)
            {
                ModelState.AddModelError("Input.Resume", "File size cannot exceed 5MB.");
                return Page();
            }

            // Save the file
            var uploadsFolder = Path.Combine(_environment.WebRootPath, "uploads");
            if (!Directory.Exists(uploadsFolder)) Directory.CreateDirectory(uploadsFolder);
            var uniqueFileName = Guid.NewGuid().ToString() + "_" + Input.Resume.FileName;
            var filePath = Path.Combine(uploadsFolder, uniqueFileName);

            using (var fileStream = new FileStream(filePath, FileMode.Create))
            {
                await Input.Resume.CopyToAsync(fileStream);
            }

            // 3. Data Sanitization (WhoAmI)
            var sanitizedWhoAmI = HtmlEncoder.Default.Encode(Input.WhoAmI);

            // 4. Create User Object
            var user = new ApplicationUser
            {
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                Gender = Input.Gender,
                Email = Input.Email,
                DateOfBirth = Input.DateOfBirth,
                ResumePath = "/uploads/" + uniqueFileName,
                WhoAmI = sanitizedWhoAmI,

                // Encrypt NRIC
                NRIC = _encryptionService.EncryptData(Input.NRIC),

                // Security Defaults
                FailedLoginAttempts = 0,
                LockoutEnd = null,
                LastPasswordChangedDate = DateTime.Now
            };

            // 5. Hash Password
            var passwordHasher = new PasswordHasher<ApplicationUser>();
            user.PasswordHash = passwordHasher.HashPassword(user, Input.Password);

            // 6. Save to Database
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            // 6a. Add to password history (after user is saved and has an ID)
            var passwordHistory = new PasswordHistory
            {
                UserId = user.Id,
                PasswordHash = user.PasswordHash,
                ChangedDate = DateTime.Now
            };
            _context.PasswordHistories.Add(passwordHistory);

            // Audit Log
            var auditLog = new AuditLog
            {
                UserId = Input.Email,
                Activity = "User Registration",
                Timestamp = DateTime.Now
            };
            _context.AuditLogs.Add(auditLog);

            await _context.SaveChangesAsync();

            return RedirectToPage("/Login");
        }
    }
}