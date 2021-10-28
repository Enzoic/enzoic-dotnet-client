using System.Text;
using System.Security.Cryptography;

namespace PasswordPingClientCore.Utilities
{
    public static class Hashing
    {
        private static SHA512Managed sha512 = new SHA512Managed();
        private static SHA256Managed sha2 = new SHA256Managed();
        private static SHA1Managed sha1 = new SHA1Managed();
        private static MD5 md5 = MD5.Create();

        public static string CalcMD5(string password)
        {
            return ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public static string CalcSHA1(string password)
        {
            return ToHexString(sha1.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public static string CalcSHA256(string password)
        {
            return ToHexString(sha2.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        private static char ToHexDigit(int i)
        {
            if (i < 10)
                return (char)(i + '0');
            return (char)(i - 10 + 'a');
        }

        public static string ToHexString(byte[] bytes)
        {
            var chars = new char[bytes.Length * 2];

            for (int i = 0; i < bytes.Length; i++)
            {
                chars[2 * i] = ToHexDigit(bytes[i] / 16);
                chars[2 * i + 1] = ToHexDigit(bytes[i] % 16);
            }

            return new string(chars);
        }
    }
}
