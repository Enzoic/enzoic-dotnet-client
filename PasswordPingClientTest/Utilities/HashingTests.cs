using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PasswordPingClient.Enums;
using PasswordPingClient.Utilities;

namespace PasswordPingTest.Utilities
{
    [TestClass]
    public class HashingTests
    {
        [TestMethod]
        public void TestCalcPasswordHash()
        {
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.BCrypt, "12345", "$2a$12$2bULeXwv2H34SXkT1giCZe"), "$2a$12$2bULeXwv2H34SXkT1giCZeJW7A6Q0Yfas09wOCxoIC44fDTYq44Mm");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CRC32, "password"), "901924565");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm1, "123456", "00new00"), "cee66db36504915f48b2d545803a4494bb1b76b6e9d8ba8c0e6083ff9b281abdef31f6172548fdcde4000e903c5a98a1178c414f7dbf44cffc001aee8e1fe206");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm2, "123456", "123"), "579d9ec9d0c3d687aaa91289ac2854e4");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.IPBoard_MyBB, "123456", "12345"), "96c06579d8dfc66d81f05aab51a9b284");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.MD5, "123456"), "e10adc3949ba59abbe56e057f20f883e");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PHPBB3, "123456789", "$H$993WP3hbz"), "$H$993WP3hbzy0N22X06wxrCc3800D2p41");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA1, "123456"), "7c4a8d09ca3762af61e59520943dc26494f8941b");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA256, "123456"), "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA512, "123456"), "ba3253876aed6bc22d4a6ff53d8406c6ad864195ed144ab5c87621b6c233b548baeae6956df346ec8c17f5ea10f35ee3cbc514797ed7ddd3145464e2a0bab413");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.vBulletinPost3_8_5, "123456", "123"), "77d3b7ed9db7d236b9eac8262d27f6a5");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.vBulletinPre3_8_5, "123456", "123"), "77d3b7ed9db7d236b9eac8262d27f6a5");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.MD5Crypt, "123456", "$1$4d3c09ea"), "$1$4d3c09ea$hPwyka2ToWFbLTOq.yFjf.");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm4, "1234", "$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W"), "$2y$12$Yjk3YjIzYWIxNDg0YWMzZOpp/eAMuWCD3UwX1oYgRlC1ci4Al970W");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm5, "password", "123456"), "69e7ade919a318d8ecf6fd540bad9f169bce40df4cae4ac1fb6be2c48c514163");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.osCommerce_AEF, "password", "123"), "d2bc2f8d09990ebe87c809684fd78c66");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.DESCrypt, "qwerty", "yD"), "yDba8kDA7NUDQ");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.DESCrypt, "password", "X."), "X.OPW8uuoq5N.");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.MySQLPre4_1, "password"), "5d2e19393cc5ef67");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.MySQLPost4_1, "test"), "*94bdcebe19083ce2a1f959fd02f964c7af4cfc29");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PeopleSoft, "TESTING"), "3weP/BR8RHPLP2459h003IgJxyU=");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PunBB, "password", "123"), "0c9a0dc3dd0b067c016209fd46749c281879069e");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PartialMD5_20, "password"), "5f4dcc3b5aa765d61d83");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.AVE_DataLife_Diferior, "password"), "696d29e0940a4957748fe3fc9efd22a3");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.DjangoMD5, "password", "c6218"), "md5$c6218$346abd81f2d88b4517446316222f4276");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.DjangoSHA1, "password", "c6218"), "sha1$c6218$161d1ac8ab38979c5a31cbaba4a67378e7e60845");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PartialMD5_29, "password"), "5f4dcc3b5aa765d61d8327deb882c");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.PliggCMS, "password", "123"), "1230de084f38ace8e3d82597f55cc6ad5d6001568e6");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.RunCMS_SMF1_1, "password", "123"), "0de084f38ace8e3d82597f55cc6ad5d6001568e6");
        }

        [TestMethod]
        public void TestCalcArgon2()
        {
            Assert.AreEqual("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.CalcArgon2("123456", "saltysalt"));
            Assert.AreEqual("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.CalcArgon2("123456", "$argon2d$v=19$m=1024,t=3,p=2,l=20$c2FsdHlzYWx0"));
            Assert.AreEqual("$argon2i$v=19$m=1024,t=2,p=2$c29tZXNhbHQ$bBKumUNszaveOgEhcaWl6r6Y91Y", Hashing.CalcArgon2("password", "$argon2i$v=19$m=1024,t=2,p=2,l=20$c29tZXNhbHQ"));
            Assert.AreEqual("$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$M2X6yo+ZZ8ROwC7MB6/+1yMhGytTzDczBMgo3Is7ptY", Hashing.CalcArgon2("password", "$argon2i$v=19$m=4096,t=2,p=4,l=32$c29tZXNhbHQ"));
            Assert.AreEqual("$argon2i$v=19$m=4096,t=2,p=4$c29tZXNhbHQ$ZPidoNOWM3jRl0AD+3mGdZsq+GvHprGL", Hashing.CalcArgon2("password", "$argon2i$v=19$m=4096,t=2,p=4,l=24$c29tZXNhbHQ"));

            Assert.AreEqual("$argon2d$v=19$m=1024,t=3,p=2$c2FsdHlzYWx0$EklGIPtCSWb3IS+q4IQ7rwrwm2o", Hashing.CalcArgon2("123456", "$argon2d$v=19$m=10d4,t=ejw,p=2$c2FsdHlzYWx0"));
        }
    }
}
