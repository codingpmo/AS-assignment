using Microsoft.EntityFrameworkCore;

namespace AceJobAgency.Models
{
    public class AuthDbContext : DbContext
    {
        // Constructor that passes configuration options (like connection string) to the base class
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

        // Table 1: Stores all user registration data
        public DbSet<ApplicationUser> Users { get; set; }

        // Table 2: Stores the history of logins/logouts for the Audit Log requirement
        public DbSet<AuditLog> AuditLogs { get; set; }

        // Table 3: Stores password history for password reuse prevention
        public DbSet<PasswordHistory> PasswordHistories { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Configure the relationship between ApplicationUser and PasswordHistory
            modelBuilder.Entity<ApplicationUser>()
                .HasMany(u => u.PasswordHistories)
                .WithOne(ph => ph.User)
                .HasForeignKey(ph => ph.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}