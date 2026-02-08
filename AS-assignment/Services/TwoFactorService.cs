using System.Security.Cryptography;
using System.Text;
using AceJobAgency.Models;

namespace AceJobAgency.Services
{
    public class TwoFactorService
    {
        private const int BackupCodeCount = 10;
        private const int BackupCodeLength = 8;
        private const string Base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

        /// <summary>
        /// Generates a new TOTP secret for the user (Base32 encoded random bytes).
        /// </summary>
        public string GenerateTwoFactorSecret()
        {
            byte[] randomBytes = new byte[20];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
            }
            return Base32Encode(randomBytes);
        }

        /// <summary>
        /// Generates backup codes for account recovery.
        /// </summary>
        public List<string> GenerateBackupCodes()
        {
            var codes = new List<string>();
            using (var rng = RandomNumberGenerator.Create())
            {
                for (int i = 0; i < BackupCodeCount; i++)
                {
                    byte[] tokenData = new byte[BackupCodeLength];
                    rng.GetBytes(tokenData);
                    string code = Convert.ToBase64String(tokenData)
                        .Replace("+", "")
                        .Replace("/", "")
                        .Replace("=", "")
                        .Substring(0, Math.Min(BackupCodeLength, Convert.ToBase64String(tokenData).Length - 2));
                    codes.Add(code);
                }
            }
            return codes;
        }

        /// <summary>
        /// Verifies a TOTP code using RFC 6238 implementation.
        /// Accepts the current code and codes from ±1 time window (30-second steps).
        /// </summary>
        public bool VerifyTwoFactorCode(string secret, string code)
        {
            try
            {
                if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(code) || code.Length != 6)
                {
                    return false;
                }

                if (!code.All(char.IsDigit))
                {
                    return false;
                }

                // Decode the Base32 secret
                byte[] secretBytes = Base32Decode(secret);
                if (secretBytes == null || secretBytes.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine($"Failed to decode secret: {secret}");
                    return false;
                }

                System.Diagnostics.Debug.WriteLine($"Decoded secret bytes length: {secretBytes.Length}");

                // Check current, previous, and next time steps (each 30 seconds)
                long currentTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                
                for (int offset = -1; offset <= 1; offset++)
                {
                    long timeStep = (currentTime + (offset * 30)) / 30;
                    string totpCode = GenerateTotpCode(secretBytes, timeStep);
                    
                    System.Diagnostics.Debug.WriteLine($"Offset {offset}: Generated TOTP={totpCode}, Input Code={code}");
                    
                    if (totpCode == code)
                    {
                        System.Diagnostics.Debug.WriteLine("TOTP verification successful!");
                        return true;
                    }
                }

                return false;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"2FA Verification Error: {ex.Message}\n{ex.StackTrace}");
                return false;
            }
        }

        /// <summary>
        /// Generates a TOTP code for a given time step using RFC 6238.
        /// </summary>
        private string GenerateTotpCode(byte[] secret, long timeStep)
        {
            byte[] message = new byte[8];
            for (int i = 7; i >= 0; i--)
            {
                message[i] = (byte)(timeStep & 0xff);
                timeStep >>= 8;
            }

            using (var hmac = new HMACSHA1(secret))
            {
                byte[] hash = hmac.ComputeHash(message);
                int offset = hash[hash.Length - 1] & 0x0f;
                int otp = ((hash[offset] & 0x7f) << 24)
                    | ((hash[offset + 1] & 0xff) << 16)
                    | ((hash[offset + 2] & 0xff) << 8)
                    | (hash[offset + 3] & 0xff);

                otp = otp % 1000000;
                return otp.ToString("D6");
            }
        }

        /// <summary>
        /// Verifies if a backup code is valid and removes it from the list.
        /// </summary>
        public bool VerifyAndRemoveBackupCode(ApplicationUser user, string backupCode)
        {
            if (user.BackupCodes == null || user.BackupCodes.Count == 0)
            {
                return false;
            }

            try
            {
                var codes = user.BackupCodes;
                if (codes.Contains(backupCode))
                {
                    codes.Remove(backupCode);
                    return true;
                }
            }
            catch
            {
                return false;
            }

            return false;
        }

        /// <summary>
        /// Generates a QR code URL for authenticator apps.
        /// </summary>
        public string GenerateQrCodeUrl(string secret, string email)
        {
            var issuer = "AceJobAgency";
            var encodedEmail = Uri.EscapeDataString(email);
            var encodedSecret = Uri.EscapeDataString(secret);

            return $"otpauth://totp/{encodedEmail}?secret={encodedSecret}&issuer={issuer}";
        }

        /// <summary>
        /// Base32 encoding (RFC 4648) helper - properly encodes bytes to Base32 string.
        /// </summary>
        private static string Base32Encode(byte[] input)
        {
            if (input == null || input.Length == 0)
                return string.Empty;

            StringBuilder sb = new StringBuilder();
            int bitCount = 0;
            int value = 0;

            foreach (byte b in input)
            {
                value = (value << 8) | b;
                bitCount += 8;

                while (bitCount >= 5)
                {
                    bitCount -= 5;
                    int index = (value >> bitCount) & 0x1f;
                    sb.Append(Base32Alphabet[index]);
                }
            }

            if (bitCount > 0)
            {
                int index = (value << (5 - bitCount)) & 0x1f;
                sb.Append(Base32Alphabet[index]);
            }

            return sb.ToString();
        }

        /// <summary>
        /// Base32 decoding (RFC 4648) helper - properly decodes Base32 string to bytes.
        /// </summary>
        private static byte[] Base32Decode(string input)
        {
            if (string.IsNullOrEmpty(input))
                return null;

            input = input.ToUpper().Replace(" ", "").Replace("=", "");
            
            List<byte> result = new List<byte>();
            int bitCount = 0;
            int value = 0;

            foreach (char c in input)
            {
                int index = Base32Alphabet.IndexOf(c);
                if (index < 0)
                {
                    System.Diagnostics.Debug.WriteLine($"Invalid Base32 character: {c}");
                    return null;
                }

                value = (value << 5) | index;
                bitCount += 5;

                if (bitCount >= 8)
                {
                    bitCount -= 8;
                    result.Add((byte)((value >> bitCount) & 0xff));
                }
            }

            return result.ToArray();
        }
    }
}
