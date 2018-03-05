using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PasswordPingClient;
using PasswordPingClient.Enums;

namespace PasswordPingClientTest
{
    /// <summary>
    /// These are actually live tests and require a valid API key and Secret to be set in your environment variables.
    /// Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
    /// </summary>
    [TestClass]
    public class PasswordPingTests
    {
        [TestMethod]
        public void TestConstructor()
        {
            Assert.IsTrue(CheckConstructorWithParameters(null, null));
            Assert.IsTrue(CheckConstructorWithParameters("test", null));
            Assert.IsTrue(CheckConstructorWithParameters(null, "test"));
            Assert.IsTrue(CheckConstructorWithParameters("", ""));
            Assert.IsTrue(CheckConstructorWithParameters("", "test"));
            Assert.IsTrue(CheckConstructorWithParameters("test", ""));
            Assert.IsFalse(CheckConstructorWithParameters("test", "test"));
        }

        [TestMethod]
        public void TestCheckCredentials()
        {
            PasswordPing passwordping = GetPasswordPing();

            bool exposed = passwordping.CheckCredentials("test@passwordping.com", "123456");
            Assert.IsTrue(exposed);

            exposed = passwordping.CheckCredentials("test@passwordping.com", "notvalid");
            Assert.IsFalse(exposed);

            exposed = passwordping.CheckCredentials("testpwdpng445", "testpwdpng4452");
            Assert.IsTrue(exposed);

            exposed = passwordping.CheckCredentials("testpwdpng445", "notvalid");
            Assert.IsFalse(exposed);

            exposed = passwordping.CheckCredentials("testpwdpng445", "testpwdpng4452", null, new PasswordType[] { PasswordType.vBulletinPost3_8_5 });
            Assert.IsFalse(exposed);

            exposed = passwordping.CheckCredentials("testpwdpng445", "testpwdpng4452", new DateTime(2018, 3, 1), null);
            Assert.IsFalse(exposed);
        }

        [TestMethod]
        public void TestGetExposuresForUser()
        {
            PasswordPing passwordping = GetPasswordPing();

            // test bad value
            ExposuresResponse result = passwordping.GetExposuresForUser("@@bogus-username@@");
            Assert.IsTrue(result.Count == 0);
            Assert.IsTrue(result.Exposures.Length == 0);

            // test a known good value
            result = passwordping.GetExposuresForUser("eicar");
            Assert.AreEqual(6, result.Count);
            Assert.AreEqual(6, result.Exposures.Length);
            CollectionAssert.AreEqual(new String[] {
                "5820469ffdb8780510b329cc",
                "58258f5efdb8780be88c2c5d",
                "582a8e51fdb87806acc426ff",
                "583d2f9e1395c81f4cfa3479",
                "59ba1aa369644815dcd8683e",
                "59cae0ce1d75b80e0070957c" }, result.Exposures);
        }

        [TestMethod]
        public void TestGetExposureDetails()
        {
            PasswordPing passwordping = GetPasswordPing();

            // test bad value
            ExposureDetails result = passwordping.GetExposureDetails("111111111111111111111111");
            Assert.AreEqual(null, result);

            // test a known good value
            result = passwordping.GetExposureDetails("5820469ffdb8780510b329cc");
            Assert.IsTrue(result != null);
            Assert.AreEqual("5820469ffdb8780510b329cc", result.ID);
            Assert.AreEqual("last.fm", result.Title);
            Assert.AreEqual("Music", result.Category);
            Assert.AreEqual(634661568000000000L, result.Date.Value.Ticks);
            Assert.AreEqual("MD5", result.PasswordType);
            CollectionAssert.AreEqual(new String[] { "Emails", "Passwords", "Usernames", "Website Activity" }, result.ExposedData);
            Assert.AreEqual(43570999, result.Entries);
            Assert.AreEqual(1218513, result.DomainsAffected);
        }

        [TestMethod]
        public void TestCheckPassword()
        {
            PasswordPing passwordping = GetPasswordPing();

            Assert.IsFalse(passwordping.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"));
            Assert.IsTrue(passwordping.CheckPassword("123456"));

            // try with out parameters
            bool revealedInExposure;
            int? relativeExposureFrequency;

            Assert.IsFalse(passwordping.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(false, revealedInExposure);
            Assert.IsNull(relativeExposureFrequency);

            Assert.IsTrue(passwordping.CheckPassword("`!(&,<:{`>", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(false, revealedInExposure);
            Assert.IsNull(relativeExposureFrequency);

            Assert.IsTrue(passwordping.CheckPassword("password", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(true, revealedInExposure);
            Assert.IsTrue(relativeExposureFrequency > 0);
        }

        // HELPER METHODS

        private bool CheckConstructorWithParameters(String apiKey, String secret)
        {
            try
            {
                new PasswordPing(apiKey, secret);
            }
            catch (Exception)
            {
                return true;
            }

            return false;
        }

        private PasswordPing GetPasswordPing()
        {
            return new PasswordPing(GetAPIKey(), GetAPISecret());
        }

        private String GetAPIKey()
        {
            // set these env vars to run live tests
            return Environment.GetEnvironmentVariable("PP_API_KEY");
        }

        private String GetAPISecret()
        {
            // set these env vars to run live tests
            return Environment.GetEnvironmentVariable("PP_API_SECRET");
        }
    }
}
