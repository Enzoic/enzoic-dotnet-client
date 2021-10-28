using System;
using PasswordPingClientCore;
using Xunit;

namespace PasswordPingClientCoreTest
{
    /// <summary>
    /// These are actually live tests and require a valid API key and Secret to be set in your environment variables.
    /// Set an env var for PP_API_KEY and PP_API_SECRET with the respective values prior to running the tests.
    /// </summary>
    public class PasswordPingCoreTests
    {

        public PasswordPingCoreTests()
        {
            Environment.SetEnvironmentVariable("PP_API_KEY", "d7f84daff45045e080e62e8f7eb6a9c7");
            Environment.SetEnvironmentVariable("PP_API_SECRET", "=UuTmZEDrW6c8XBkTZyrZ94NHt1p3pk*");
        }
        
        [Fact]
        public void TestConstructor()
        {
            Assert.True(CheckConstructorWithParameters(null, null));
            Assert.True(CheckConstructorWithParameters("test", null));
            Assert.True(CheckConstructorWithParameters(null, "test"));
            Assert.True(CheckConstructorWithParameters("", ""));
            Assert.True(CheckConstructorWithParameters("", "test"));
            Assert.True(CheckConstructorWithParameters("test", ""));
            Assert.False(CheckConstructorWithParameters("test", "test"));
        }

        [Fact]
        public void TestGetExposuresForUser()
        {
            PasswordPing passwordping = GetPasswordPing();

            // test bad value
            ExposuresResponse result = passwordping.GetExposuresForUser("@@bogus-username@@");
            Assert.True(result.Count == 0);
            Assert.True(result.Exposures.Length == 0);

            // test a known good value
            result = passwordping.GetExposuresForUser("eicar");
            Assert.Equal(8, result.Count);
            Assert.Equal(8, result.Exposures.Length);
            Assert.Equal(new[] {
                "5820469ffdb8780510b329cc",
                "58258f5efdb8780be88c2c5d",
                "582a8e51fdb87806acc426ff",
                "583d2f9e1395c81f4cfa3479",
                "59ba1aa369644815dcd8683e",
                "59cae0ce1d75b80e0070957c",
                "5bc64f5f4eb6d894f09eae70",
                "5bdcb0944eb6d8a97cfacdff"                
            },
                    result.Exposures);
        }
        
        /*[TestMethod]
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
        }*/

        [Fact]
        public void TestCheckPassword()
        {
            PasswordPing passwordping = GetPasswordPing();

            Assert.False(passwordping.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd"));
            Assert.True(passwordping.CheckPassword("123456"));

            // try with out parameters
            bool revealedInExposure;
            int? relativeExposureFrequency;

            Assert.False(passwordping.CheckPassword("kjdlkjdlksjdlskjdlskjslkjdslkdjslkdjslkd", out revealedInExposure, out relativeExposureFrequency));
            Assert.False(revealedInExposure);
            Assert.Null(relativeExposureFrequency);

            Assert.True(passwordping.CheckPassword("`!(&,<:{`>", out revealedInExposure, out relativeExposureFrequency));
            Assert.False(revealedInExposure);
            Assert.Null(relativeExposureFrequency);

            Assert.True(passwordping.CheckPassword("password", out revealedInExposure, out relativeExposureFrequency));
            Assert.True(revealedInExposure);
            Assert.True(relativeExposureFrequency > 0);
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
