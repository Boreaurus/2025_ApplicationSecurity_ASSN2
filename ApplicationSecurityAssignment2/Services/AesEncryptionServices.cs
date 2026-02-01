using System.Security.Cryptography;
using System.Text;

namespace ApplicationSecurityAssignment2.Services
{
    public sealed class AesEncryptionService
    {
        private readonly byte[] _key;

        // keyBase64 should be 32 bytes (256-bit) when Base64-decoded
        public AesEncryptionService(string keyBase64)
        {
            _key = Convert.FromBase64String(keyBase64);
            if (_key.Length != 32)
                throw new InvalidOperationException("AES key must be 32 bytes (256-bit) after Base64 decoding.");
        }

        public (string cipherTextBase64, string ivBase64) Encrypt(string plainText)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            aes.GenerateIV(); // random IV each time
            var iv = aes.IV;

            using var encryptor = aes.CreateEncryptor(aes.Key, iv);
            var plainBytes = Encoding.UTF8.GetBytes(plainText);
            var cipherBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

            return (Convert.ToBase64String(cipherBytes), Convert.ToBase64String(iv));
        }

        public string Decrypt(string cipherTextBase64, string ivBase64)
        {
            using var aes = Aes.Create();
            aes.Key = _key;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            var iv = Convert.FromBase64String(ivBase64);
            var cipherBytes = Convert.FromBase64String(cipherTextBase64);

            using var decryptor = aes.CreateDecryptor(aes.Key, iv);
            var plainBytes = decryptor.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);

            return Encoding.UTF8.GetString(plainBytes);
        }
    }
}
