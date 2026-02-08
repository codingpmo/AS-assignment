using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class ApplicationUser
    {
        [Key]
        public int Id { get; set; }

        // --- Business Fields (Ace Job Agency) ---
        [Required]
        public string FirstName { get; set; }

        [Required]
        public string LastName { get; set; }

        [Required]
        public string Gender { get; set; }

        [Required]
        public string NRIC { get; set; } // Must be encrypted 

        [Required]
        [EmailAddress]
        public string Email { get; set; } // Must be unique 

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        [DataType(DataType.Date)]
        public DateTime DateOfBirth { get; set; }

        public string ResumePath { get; set; } // Stores file path (.docx/.pdf)

        public string WhoAmI { get; set; } // Allow special chars 

        // --- Security Fields ---
        public string? SessionId { get; set; } // For "Detect multiple logins" 
        public int FailedLoginAttempts { get; set; } // For "Account lockout" 
        public DateTime? LockoutEnd { get; set; } // For "Account lockout" 
        public DateTime LastPasswordChangedDate { get; set; } = DateTime.Now; // For "Password age" 
        public string? PreviousPasswordHash1 { get; set; } // For "Password History" 
        public string? PreviousPasswordHash2 { get; set; }

        // --- Two-Factor Authentication (2FA) ---
        public bool IsTwoFactorEnabled { get; set; } = false;
        public string? TwoFactorSecret { get; set; } // Base32 encoded secret for TOTP
        public DateTime? TwoFactorSetupDate { get; set; }
        public List<string>? BackupCodes { get; set; } // JSON-serialized list of backup codes

        // --- Password Age Enforcement ---
        public int MinimumPasswordAgeDays { get; set; } = 1; // Minimum days before password can be changed
        public int MaximumPasswordAgeDays { get; set; } = 90; // Maximum days before password must be changed
        public bool HasCompletedFirstPasswordChange { get; set; } = false; // Track if user has changed password after registration

        // Navigation property
        public ICollection<PasswordHistory>? PasswordHistories { get; set; }
    }
}