using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using AceJobAgency.Models;
using AceJobAgency.Services;

namespace AceJobAgency.Pages
{
    public class IndexModel : PageModel
    {
        private readonly AuthDbContext _context;
        private readonly EncryptionService _encryptionService;

        public IndexModel(AuthDbContext context, EncryptionService encryptionService)
        {
            _context = context;
            _encryptionService = encryptionService;
        }

        public ApplicationUser CurrentUser { get; set; }
        public string DecryptedNRIC { get; set; }

        public IActionResult OnGet()
        {
            // 1. Check if Session Exists
            var userEmail = HttpContext.Session.GetString("UserEmail");
            if (string.IsNullOrEmpty(userEmail))
            {
                return RedirectToPage("/Login");
            }

            // 2. Fetch User from Database
            CurrentUser = _context.Users.FirstOrDefault(u => u.Email == userEmail);
            if (CurrentUser == null)
            {
                return RedirectToPage("/Login");
            }

            // 3. SINGLE SESSION CHECK (Requirement: Detect multiple logins)
            // Compare the SessionId in the browser (AuthToken) with the SessionId in the Database.
            // If they are different, it means a newer login occurred elsewhere.
            var currentSessionToken = HttpContext.Session.GetString("AuthToken");

            if (CurrentUser.SessionId != currentSessionToken)
            {
                // Force Logout
                HttpContext.Session.Clear();
                return RedirectToPage("/Login");
            }

            // 4. Decrypt NRIC (Requirement: Decryption of customer data)
            // We use the helper service to turn the gibberish back into the original ID
            DecryptedNRIC = _encryptionService.DecryptData(CurrentUser.NRIC);

            return Page();
        }

        // 5. Logout Handler
        public IActionResult OnPostLogout()
        {
            // Requirement: Perform proper and safe logout (Clear session)
            HttpContext.Session.Clear();
            return RedirectToPage("/Login");
        }
    }
}