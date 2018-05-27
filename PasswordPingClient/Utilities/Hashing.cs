using System;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using System.Data.HashFunction.CRCStandards;
using PasswordPingClient.Enums;
using Liphsoft.Crypto.Argon2;

namespace PasswordPingClient.Utilities
{
    public static class Hashing
    {
        private static SHA512Managed sha512 = new SHA512Managed();
        private static SHA256Managed sha2 = new SHA256Managed();
        private static SHA1Managed sha1 = new SHA1Managed();
        private static MD5 md5 = MD5.Create();
        private static CRC32 crc32 = new CRC32();

        public static string CalcPasswordHash(PasswordType passwordType, string password, string salt = "")
        {
            switch (passwordType)
            {
                case PasswordType.BCrypt:
                    return CalcBCrypt(password, salt);
                case PasswordType.CRC32:
                    return CalcCRC32(password);
                case PasswordType.CustomAlgorithm1:
                    return CalcCustomAlgorithm1(password, salt);
                case PasswordType.CustomAlgorithm2:
                    return CalcCustomAlgorithm2(password, salt);
                case PasswordType.IPBoard_MyBB:
                    return CalcIPBoardHash(password, salt);
                case PasswordType.MD5:
                    return CalcMD5(password);
                case PasswordType.PHPBB3:
                    return CalcPHPBB3(password, salt);
                case PasswordType.SHA1:
                    return CalcSHA1(password);
                case PasswordType.SHA256:
                    return CalcSHA256(password);
                case PasswordType.SHA512:
                    return CalcSHA512(password);
                case PasswordType.vBulletinPost3_8_5:
                case PasswordType.vBulletinPre3_8_5:
                    return CalcVBulletinHash(password, salt);
                case PasswordType.CustomAlgorithm4:
                    return CalcCustomAlgorithm4(password, salt);
                case PasswordType.MD5Crypt:
                    return CalcMD5Crypt(password, salt);
                case PasswordType.CustomAlgorithm5:
                    return CalcCustomAlgorithm5(password, salt);
                case PasswordType.DESCrypt:
                    return CalcDESCrypt(password, salt);
                case PasswordType.SCrypt:
                    return CalcSCrypt(password, salt);
                case PasswordType.MySQLPre4_1:
                    return CalcMySQLPre4_1(password);
                case PasswordType.MySQLPost4_1:
                    return CalcMySQLPost4_1(password);
                case PasswordType.PeopleSoft:
                    return CalcPeopleSoft(password);
                case PasswordType.PunBB:
                    return CalcPunBB(password, salt);
                case PasswordType.osCommerce_AEF:
                    return ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(salt + password)));
                case PasswordType.PartialMD5_20:
                    return CalcMD5(password).Substring(0, 20);
                case PasswordType.AVE_DataLife_Diferior:
                    return CalcMD5(CalcMD5(password));
                case PasswordType.DjangoMD5:
                    return CalcDjangoMD5(password, salt);
                case PasswordType.DjangoSHA1:
                    return CalcDjangoSHA1(password, salt);
                case PasswordType.PartialMD5_29:
                    return CalcMD5(password).Substring(0, 29);
                case PasswordType.PliggCMS:
                    return salt + CalcSHA1(salt + password); // salt is prepended to hash
                case PasswordType.RunCMS_SMF1_1:
                    return CalcSHA1(salt + password); // salt is username

                default:
                    throw new Exception("Unsupported PasswordType in PasswordHashCalc");
            }
        }

        public static string CalcBCrypt(string password, string salt)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, salt);
        }

        public static string CalcVBulletinHash(string password, string salt)
        {
            return ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(CalcMD5(password) + salt)));
        }

        public static string CalcIPBoardHash(string password, string salt)
        {
            return ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(CalcMD5(salt) + CalcMD5(password))));
        }

        public static string CalcCRC32(string password)
        {
            return BitConverter.ToInt32(crc32.ComputeHash(Encoding.UTF8.GetBytes(password)), 0).ToString();
        }

        public static string CalcPHPBB3(string password, string salt)
        {
            return CryptSharp.PhpassCrypter.Phpass.Crypt(password, salt);
        }

        public static string CalcCustomAlgorithm1(string password, string salt) // Leet CC
        {
            // SHA-512(pass.salt) XOR whirlpool(salt.pass)
            string toWhirlpool = salt + password;
            string toSha = password + salt;

            byte[] sha512Out = sha512.ComputeHash(Encoding.UTF8.GetBytes(toSha));

            WhirlpoolDigest digest = new WhirlpoolDigest();
            digest.BlockUpdate(Encoding.UTF8.GetBytes(toWhirlpool), 0, toWhirlpool.Length);
            byte[] whirlpoolOut = new byte[digest.GetByteLength()];
            digest.DoFinal(whirlpoolOut, 0);

            // xor together and convert to hex
            byte[] finalOut = exclusiveOR(sha512Out, whirlpoolOut);

            return ToHexString(finalOut);
        }

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

        public static string CalcSHA512(string password)
        {
            return ToHexString(sha512.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public static string CalcCustomAlgorithm2(string password, string salt)
        {
            return ToHexString(md5.ComputeHash(Encoding.UTF8.GetBytes(password + salt)));
        }

        public static string CalcCustomAlgorithm4(string password, string salt)
        {
            return BCrypt.Net.BCrypt.HashPassword(CalcMD5(password), salt);
        }

        public static string CalcMD5Crypt(string password, string salt)
        {
            return CryptSharp.MD5Crypter.MD5.Crypt(Encoding.UTF8.GetBytes(password), salt);
        }

        public static string CalcCustomAlgorithm5(string password, string salt)
        {
            return CalcSHA256(CalcMD5(password + salt));
        }

        public static string CalcDESCrypt(string password, string salt)
        {
            return CryptSharp.TraditionalDesCrypter.TraditionalDes.Crypt(Encoding.UTF8.GetBytes(password), salt);
        }

        public static string CalcSCrypt(string password, string salt)
        {
            return CryptSharp.Sha256Crypter.Sha256.Crypt(Encoding.UTF8.GetBytes(password), salt);
        }

        public static string CalcMySQLPre4_1(string password)
        {
            uint result1;
            uint result2;
            uint nr = 1345345333;
            uint add = 7;
            uint nr2 = 0x12345671;
            uint tmp;

            foreach (char c in password)
            {
                if (c == ' ' || c == '\t')
                    continue;

                tmp = c;
                nr ^= (((nr & 63) + add) * tmp) + (nr << 8);
                nr2 += (nr2 << 8) ^ nr;
                add += tmp;
            }

            result1 = nr & (((uint)1 << 31) - 1);
            result2 = nr2 & (((uint)1 << 31) - 1);

            return result1.ToString("x") + result2.ToString("x");
        }

        public static string CalcMySQLPost4_1(string password)
        {
            return "*" + ToHexString(sha1.ComputeHash(sha1.ComputeHash(Encoding.UTF8.GetBytes(password))));
        }

        public static string CalcPeopleSoft(string password)
        {
            return Convert.ToBase64String(sha1.ComputeHash(Encoding.Unicode.GetBytes(password)));
        }

        public static string CalcPunBB(string password, string salt)
        {
            return CalcSHA1(salt + CalcSHA1(password));
        }

        public static string CalcCustomAlgorithm6(string password, string salt)
        {
            return CalcSHA1(password + salt);
        }

        public static string CalcDjangoMD5(string password, string salt)
        {
            return "md5$" + salt + "$" + CalcMD5(salt + password);
        }

        public static string CalcDjangoSHA1(string password, string salt)
        {
            return "sha1$" + salt + "$" + CalcSHA1(salt + password);
        }

        public static string CalcArgon2(string password, string salt)
        {
            // defaults
            uint iterations = 3;
            uint memoryCost = 1024;
            uint parallelism = 2;
            uint hashLength = 20;
            Argon2Type argonType = Argon2Type.Argon2d;
            string justSalt = salt;

            // check if salt has settings encoded in it
            if (salt.StartsWith("$argon2"))
            {
                // apparently has settings encoded in it - use these
                if (salt.StartsWith("$argon2i"))
                    argonType = Argon2Type.Argon2i;

                String[] saltComponents = salt.Split('$');
                if (saltComponents.Length == 5)
                {
                    // make sure Base64 encoded salt length is a multiple of 4 - if not pad 
                    justSalt = Encoding.UTF8.GetString(DecodeBase64(saltComponents[4]));
                    String[] saltParams = saltComponents[3].Split(',');

                    foreach (string saltParam in saltParams)
                    {
                        String[] saltParamValues = saltParam.Split('=');
                        switch (saltParamValues[0])
                        {
                            case "t":
                                if (!uint.TryParse(saltParamValues[1], out iterations))
                                    iterations = 3;
                                break;
                            case "m":
                                if (!uint.TryParse(saltParamValues[1], out memoryCost))
                                    memoryCost = 1024;
                                break;
                            case "p":
                                if (!uint.TryParse(saltParamValues[1], out parallelism))
                                    parallelism = 2;
                                break;
                            case "l":
                                if (!uint.TryParse(saltParamValues[1], out hashLength))
                                    hashLength = 20;
                                break;
                        }

                    }
                }
            }

            return new PasswordHasher(iterations, memoryCost, parallelism, argonType, hashLength).Hash(password, justSalt);           
        }

        public static byte[] exclusiveOR(byte[] one, byte[] two)
        {
            if (one.Length == two.Length)
            {
                byte[] result = new byte[one.Length];
                for (int i = 0; i < one.Length; i++)
                {
                    result[i] = (byte)(one[i] ^ two[i]);
                }

                return result;
            }
            else
            {
                throw new ArgumentException();
            }
        }

        public static string ExtractBCryptSalt(string bcryptPassword)
        {
            return bcryptPassword.Substring(0, 29);
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

        public static byte[] DecodeBase64(string base64)
        {
            int mod4 = base64.Length % 4;
            if (mod4 > 0)
            {
                base64 += new string('=', 4 - mod4);
            }

            return Convert.FromBase64String(base64);
        }
    }
}
