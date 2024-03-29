﻿using System;
using System.Text;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Digests;
using System.Data.HashFunction.CRC;
using EnzoicClient.Enums;
using Konscious.Security.Cryptography;
using CryptSharp;
using Org.BouncyCastle.Crypto;

namespace EnzoicClient.Utilities
{
    public static class Hashing
    {
        private static ICRC crc32 = CRCFactory.Instance.Create();

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
                    return CalcMD5(salt + password);
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
                case PasswordType.NTLM:
                    return CalcNTLM(password);
                case PasswordType.SHA1Dash:
                    return CalcSHA1Dash(password, salt);
                case PasswordType.SHA384:
                    return CalcSHA384(password);
                case PasswordType.CustomAlgorithm7:
                    return CalcCustomAlgorithm7(password, salt);
                case PasswordType.CustomAlgorithm8:
                    return CalcCustomAlgorithm8(password, salt);
                case PasswordType.CustomAlgorithm9:
                    return CalcCustomAlgorithm9(password, salt);
                case PasswordType.SHA512Crypt:
                    return CalcSHA512Crypt(password, salt);
                case PasswordType.CustomAlgorithm10:
                    return CalcCustomAlgorithm10(password, salt);
                case PasswordType.SHA256Crypt:
                    return CalcSHA256Crypt(password, salt);
                case PasswordType.HMACSHA1_SaltAsKey:
                    return CalcHMACSHA1SaltAsKey(password, salt);
                case PasswordType.AuthMeSHA256:
                    return CalcAuthMeSHA256(password, salt);
                default:
                    return null;
                    //throw new Exception("Unsupported PasswordType in PasswordHashCalc");
            }
        }

        public static string CalcBCrypt(string password, string salt)
        {
            return BCrypt.Net.BCrypt.HashPassword(password, salt);
        }

        public static string CalcVBulletinHash(string password, string salt)
        {
            return CalcMD5(CalcMD5(password) + salt);
        }

        public static string CalcIPBoardHash(string password, string salt)
        {
            return CalcMD5(CalcMD5(salt) + CalcMD5(password));
        }

        public static string CalcCRC32(string password)
        {
            return BitConverter.ToInt32(crc32.ComputeHash(Encoding.UTF8.GetBytes(password)).Hash, 0).ToString();
        }

        public static string CalcPHPBB3(string password, string salt)
        {
            return CryptSharp.PhpassCrypter.Phpass.Crypt(password, salt);
        }

        public static string CalcCustomAlgorithm1(string password, string salt) // Leet CC
        {
            // SHA-512(pass.salt) XOR whirlpool(salt.pass)
            string toWhirlpool = salt + password;

            byte[] sha512Out = CalcSHA512Raw(password + salt);

            WhirlpoolDigest digest = new WhirlpoolDigest();
            digest.BlockUpdate(Encoding.UTF8.GetBytes(toWhirlpool), 0, toWhirlpool.Length);
            byte[] whirlpoolOut = new byte[digest.GetByteLength()];
            digest.DoFinal(whirlpoolOut, 0);

            // xor together and convert to hex
            byte[] finalOut = exclusiveOR(sha512Out, whirlpoolOut);

            return ToHexString(finalOut);
        }

        public static byte[] CalcMD5Raw(string password)
        {
            return CalcBouncyCastleHash<MD5Digest>(password);
        }

        public static string CalcMD5(string password)
        {
            return ToHexString(CalcMD5Raw(password));
        }

        public static byte[] CalcSHA1Raw(string password)
        {
            return CalcBouncyCastleHash<Sha1Digest>(password);
        }

        public static byte[] CalcSHA1Raw(byte[] password)
        {
            return CalcBouncyCastleHash<Sha1Digest>(password);
        }

        public static string CalcSHA1(string password)
        {
            return ToHexString(CalcSHA1Raw(password));
        }

        public static string CalcSHA1(byte[] password)
        {
            return ToHexString(CalcSHA1Raw(password));
        }
        
        public static byte[] CalcSHA256Raw(string password)
        {
            return CalcBouncyCastleHash<Sha256Digest>(password);
        }

        public static string CalcSHA256(string password)
        {
            return ToHexString(CalcSHA256Raw(password));
        }

        public static byte[] CalcSHA512Raw(string password)
        {
            return CalcBouncyCastleHash<Sha512Digest>(password);
        }

        public static string CalcSHA512(string password)
        {
            return ToHexString(CalcSHA512Raw(password));
        }

        private static byte[] CalcBouncyCastleHash<TDigest>(string value) where TDigest : IDigest, new()
        {
            return CalcBouncyCastleHash<TDigest>(Encoding.UTF8.GetBytes(value));
        }

        private static byte[] CalcBouncyCastleHash<TDigest>(byte[] value) where TDigest : IDigest, new()
        {
            TDigest hash = new TDigest();
            hash.BlockUpdate(value, 0, value.Length);
            byte[] result = new byte[hash.GetDigestSize()];
            hash.DoFinal(result, 0);
            return result;
        }

        public static string CalcCustomAlgorithm2(string password, string salt)
        {
            return CalcMD5(password + salt);
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
            return "*" + CalcSHA1((CalcSHA1Raw(password)));
        }

        public static string CalcPeopleSoft(string password)
        {
            return Convert.ToBase64String(CalcSHA1Raw(Encoding.Unicode.GetBytes(password)));
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

        public static string CalcNTLM(string password)
        {
            MD4Digest digest = new MD4Digest();
            byte[] bytes = Encoding.Unicode.GetBytes(password);
            digest.BlockUpdate(bytes, 0, bytes.Length);
            byte[] NTLMOut = new byte[16];
            digest.DoFinal(NTLMOut, 0);

            return ToHexString(NTLMOut);
        }

        public static string CalcSHA1Dash(string password, string salt)
        {
            return CalcSHA1("--" + salt + "--" + password + "--");
        }

        public static string CalcSHA384(string password)
        {
            return ToHexString(CalcBouncyCastleHash<Sha384Digest>(password));
        }

        public static string CalcCustomAlgorithm7(string password, string salt)
        {
            string derivedSalt = CalcSHA1(salt);

            HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes("d2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e"));
            return ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(derivedSalt + password)));
        }

        public static string CalcCustomAlgorithm8(string password, string salt)
        {
            return CalcSHA256(salt + password);
        }

        public static string CalcCustomAlgorithm9(string password, string salt)
        {
            string result = CalcSHA512(password + salt);
            for (int i = 0; i < 11; i++)
            {
                result = CalcSHA512(result);
            }

            return result;
        }

        public static string CalcSHA256Crypt(string password, string salt)
        {
            return Crypter.Sha256.Crypt(Encoding.UTF8.GetBytes(password), salt);
        }

        public static string CalcSHA512Crypt(string password, string salt)
        {
            return Crypter.Sha512.Crypt(Encoding.UTF8.GetBytes(password), salt);
        }
        
        public static string CalcCustomAlgorithm10(string password, string salt)
        {
            return CalcSHA512(password + ":" + salt);
        }
        
        public static string CalcHMACSHA1SaltAsKey(string password, string salt)
        {
            HMACSHA1 hmac = new HMACSHA1(Encoding.UTF8.GetBytes(salt));
            return ToHexString(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        public static string CalcAuthMeSHA256(string password, string salt)
        {
            return "$SHA$" + salt + "$" + Hashing.CalcSHA256(Hashing.CalcSHA256(password) + salt);
        }

        public static string CalcArgon2(string password, string salt)
        {
            // defaults
            int iterations = 3;
            int memoryCost = 1024;
            int parallelism = 2;
            int hashLength = 20;
            string justSalt = salt;

            Argon2 argon2 = null;

            // check if salt has settings encoded in it
            if (salt.StartsWith("$argon2"))
            {
                // apparently has settings encoded in it - use these
                if (salt.StartsWith("$argon2i"))
                {
                    argon2 = new Argon2i(Encoding.UTF8.GetBytes(password));
                }

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
                                if (!int.TryParse(saltParamValues[1], out iterations))
                                    iterations = 3;
                                break;
                            case "m":
                                if (!int.TryParse(saltParamValues[1], out memoryCost))
                                    memoryCost = 1024;
                                break;
                            case "p":
                                if (!int.TryParse(saltParamValues[1], out parallelism))
                                    parallelism = 2;
                                break;
                            case "l":
                                if (!int.TryParse(saltParamValues[1], out hashLength))
                                    hashLength = 20;
                                break;
                        }

                    }
                }
            }

            if (argon2 == null)
                argon2 = new Argon2d(Encoding.UTF8.GetBytes(password));

            argon2.DegreeOfParallelism = parallelism;
            argon2.MemorySize = memoryCost;
            argon2.Iterations = iterations;
            argon2.Salt = Encoding.UTF8.GetBytes(justSalt);

            var bytes = argon2.GetBytes(hashLength);
            var result = BitConverter.ToString(bytes).Replace("-", "").ToLower();
            return result;
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
