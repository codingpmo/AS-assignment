using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace AceJobAgency.Models
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [ForeignKey("ApplicationUser")]
        public int UserId { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        public DateTime ChangedDate { get; set; }

        // Navigation property
        public ApplicationUser User { get; set; }
    }
}
