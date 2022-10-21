using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using EnzoicClient.Enums;
using EnzoicClient.Utilities;

namespace EnzoicClientTest.Utilities
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
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.NTLM, "123456"), "32ed87bdb5fdc5e9cba88547376818d4");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA1Dash, "123456", "478c8029d5efddc554bf2fe6bb2219d8c897d4a0"), "55566a759b86fbbd979b579b232f4dd214d08068");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA384, "123456"), "0a989ebc4a77b56a6e2bb7b19d995d185ce44090c13e2984b7ecc6d446d4b61ea9991b76a4c2f04b1b4d244841449454");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm7, "123456", "123456"), "a753d386613efd6d4a534cec97e73890f8ec960fe6634db6dbfb9b2aab207982");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm8, "matthew", "Dn"), "9fc389447b7eb88aff45a1069bf89fbeff89b8fb7d11a6f450583fa4c9c70503");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm9, "0rangepeel", "6kpcxVSjagLgsNCUCr-D"), "07c691fa8b022b52ac1c44cab3e056b344a7945b6eb9db727e3842b28d94fe18c17fe5b47b1b9a29d8149acbd7b3f73866cc12f0a8a8b7ab4ac9470885e052dc");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA512Crypt, "hashcat", "$6$52450745"), "$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.CustomAlgorithm10, "chatbooks", "NqXCvAHUpAWAco3hVTG5Sg0FfmJRQPKi0LvcHwylzXHhSNuWwvYdMSSGzswi0ZdJ"), "bd17b9d14010a1d4f8c8077f1be1e20b9364d9979bbcf8591337e952cc6037026aa4a2025543d39169022344b4dd1d20f499395533e35705296034bbf7e7d663");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.SHA256Crypt, "hashcat", "$5$rounds=5000$GX7BopJZJxPc/KEK"), "$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD");
            Assert.AreEqual(Hashing.CalcPasswordHash(PasswordType.AuthMeSHA256, "hashcat", "7218532375810603"), "$SHA$7218532375810603$bfede293ecf6539211a7305ea218b9f3f608953130405cda9eaba6fb6250f824");
        }

        [TestMethod]
        public void TestCalcArgon2()
        {
            Assert.AreEqual("12494620fb424966f7212faae0843baf0af09b6a", Hashing.CalcArgon2("123456", "saltysalt"));
            Assert.AreEqual("0922b87d3e71f10030b49c8ce721e6b226b935ab", Hashing.CalcArgon2("enz_eicar2$49efef5f70d47adc2db2eb397fbef5f7bc560e29", "k8=3W_hux:Tn{U}q!-CQxY+N(Z9PFe#Z"));
            Assert.AreEqual("38f7e43187a8d1ac386007f88c91a763dd983e31", Hashing.CalcArgon2("eicar_1@enzoic.com$e10adc3949ba59abbe56e057f20f883e", "r:sNmYdWHp+]wO.6?24xAqX:U|eo[6RF"));
            Assert.AreEqual("38f7e43187a8d1ac386007f88c91a763dd983e31", Hashing.CalcArgon2("eicar_1@enzoic.com$e10adc3949ba59abbe56e057f20f883e", "r:sNmYdWHp+]wO.6?24xAqX:U|eo[6RF"));
            Assert.AreEqual("f5305dcb130e3e8bb489acf041e6162ad6715616", Hashing.CalcArgon2("eicar_2@enzoic.com$7c4a8d09ca3762af61e59520943dc26494f8941b", "}Z/LG_*.Hc!R)(Ho-q@rJ42yLaAP}Zb}"));
        }    
    }
}
