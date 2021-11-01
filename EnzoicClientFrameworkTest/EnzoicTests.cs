using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using EnzoicClient;
using EnzoicClient.Enums;

namespace EnzoicClientFrameworkTest
{
    /// <summary>
    /// These are actually live tests and require a valid API key and Secret to be set in your environment variables.
    /// Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
    /// </summary>
    [TestClass]
    public class EnzoicTests
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
            Enzoic enzoic = GetEnzoic();

            bool exposed = enzoic.CheckCredentials("test@passwordping.com", "123456");
            Assert.IsTrue(exposed);

            exposed = enzoic.CheckCredentials("test@passwordping.com", "notvalid");
            Assert.IsFalse(exposed);

            exposed = enzoic.CheckCredentials("testpwdpng445", "testpwdpng4452");
            Assert.IsTrue(exposed);

            exposed = enzoic.CheckCredentials("testpwdpng445", "notvalid");
            Assert.IsFalse(exposed);

            exposed = enzoic.CheckCredentials("testpwdpng445", "testpwdpng4452", null, new PasswordType[] { PasswordType.vBulletinPost3_8_5 });
            Assert.IsFalse(exposed);

            exposed = enzoic.CheckCredentials("testpwdpng445", "testpwdpng4452", new DateTime(2018, 3, 1), null);
            Assert.IsFalse(exposed);
        }

        [TestMethod]
        public void TestGetExposuresForUser()
        {
            Enzoic enzoic = GetEnzoic();

            // test bad value
            ExposuresResponse result = enzoic.GetExposuresForUser("@@bogus-username@@");
            Assert.IsTrue(result.Count == 0);
            Assert.IsTrue(result.Exposures.Length == 0);

            // test a known good value
            result = enzoic.GetExposuresForUser("eicar");
            Assert.AreEqual(8, result.Count);
            Assert.AreEqual(8, result.Exposures.Length);
            CollectionAssert.AreEqual(new String[] {
                "5820469ffdb8780510b329cc",
                "58258f5efdb8780be88c2c5d",
                "582a8e51fdb87806acc426ff",
                "583d2f9e1395c81f4cfa3479",
                "59ba1aa369644815dcd8683e",
                "59cae0ce1d75b80e0070957c",
                "5bc64f5f4eb6d894f09eae70",
                "5bdcb0944eb6d8a97cfacdff"
            }, result.Exposures);
        }

        [TestMethod]
        public void TestGetExposureDetails()
        {
            Enzoic enzoic = GetEnzoic();

            // test bad value
            ExposureDetails result = enzoic.GetExposureDetails("111111111111111111111111");
            Assert.AreEqual(null, result);

            // test a known good value
            result = enzoic.GetExposureDetails("5820469ffdb8780510b329cc");
            Assert.IsTrue(result != null);
            Assert.AreEqual("5820469ffdb8780510b329cc", result.ID);
            Assert.AreEqual("last.fm", result.Title);
            Assert.AreEqual("Music", result.Category);
            Assert.AreEqual(634661568000000000L, result.Date.Value.Ticks);
            Assert.AreEqual("MD5", result.PasswordType);
            CollectionAssert.AreEqual(new String[] { "Emails", "Passwords", "Usernames", "Website Activity" }, result.ExposedData);
            Assert.AreEqual(81967007, result.Entries);
            Assert.AreEqual(1219053, result.DomainsAffected);
        }

        [TestMethod]
        public void TestCheckPassword()
        {
            Enzoic enzoic = GetEnzoic();

            Assert.IsFalse(enzoic.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"));
            Assert.IsTrue(enzoic.CheckPassword("123456"));

            // try with out parameters
            bool revealedInExposure;
            int? relativeExposureFrequency;

            Assert.IsFalse(enzoic.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(false, revealedInExposure);
            Assert.IsNull(relativeExposureFrequency);

            Assert.IsTrue(enzoic.CheckPassword("`!(&,<:{`>", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(false, revealedInExposure);
            Assert.IsNull(relativeExposureFrequency);

            Assert.IsTrue(enzoic.CheckPassword("password", out revealedInExposure, out relativeExposureFrequency));
            Assert.AreEqual(true, revealedInExposure);
            Assert.IsTrue(relativeExposureFrequency > 0);
        }

        // HELPER METHODS

        private bool CheckConstructorWithParameters(String apiKey, String secret)
        {
            try
            {
                new Enzoic(apiKey, secret);
            }
            catch (Exception)
            {
                return true;
            }

            return false;
        }

        private Enzoic GetEnzoic()
        {
            return new Enzoic(GetAPIKey(), GetAPISecret());
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
