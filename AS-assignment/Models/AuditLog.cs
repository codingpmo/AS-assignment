using System;
using System.ComponentModel.DataAnnotations;

namespace AceJobAgency.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string UserId { get; set; } // Stores the User's Email or ID

        [Required]
        public string Activity { get; set; } // E.g., "Login", "Logout", "Failed Login"

        [Required]
        public DateTime Timestamp { get; set; } // When it happened
    }
}