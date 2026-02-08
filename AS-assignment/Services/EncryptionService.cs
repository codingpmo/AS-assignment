using System.Security.Cryptography;
using System.Text;

namespace AceJobAgency.Services
{
    public class EncryptionService
    {
        // In a real app, store this KEY in an Environment Variable or Azure Key Vault.
        // For this assignment, we use a fixed 32-byte key (256-bit).
        private static readonly string Key = "E546C8DF278CD5931069B522E695D4F2";

        public string EncryptData(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return null;

            byte[] keyBytes = Encoding.UTF8.GetBytes(Key);
            byte[] iv = new byte[16]; // Initialization Vector (IV) for randomness

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv; // Using zero IV for simplicity in this specific assignment scope
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                {
                    byte[] inputBytes = Encoding.UTF8.GetBytes(plainText);
                    byte[] encryptedBytes = encryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Convert.ToBase64String(encryptedBytes);
                }
            }
        }

        public string DecryptData(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return null;

            byte[] keyBytes = Encoding.UTF8.GetBytes(Key);
            byte[] iv = new byte[16];

            using (var aes = Aes.Create())
            {
                aes.Key = keyBytes;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    byte[] inputBytes = Convert.FromBase64String(cipherText);
                    byte[] plainBytes = decryptor.TransformFinalBlock(inputBytes, 0, inputBytes.Length);
                    return Encoding.UTF8.GetString(plainBytes);
                }
            }
        }
    }
}