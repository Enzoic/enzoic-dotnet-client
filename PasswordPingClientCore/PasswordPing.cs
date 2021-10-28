using System;
using System.Linq;
using System.Text;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net;
using PasswordPingClientCore.Utilities;

namespace PasswordPingClientCore
{
    public class PasswordPing
    {
        private const String CREDENTIALS_API_PATH = "/credentials";
        private const String PASSWORDS_API_PATH = "/passwords";
        private const String EXPOSURES_API_PATH = "/exposures";
        private const String ACCOUNTS_API_PATH = "/accounts";
        private const String ALERTS_SERVICE_PATH = "/alert-subscriptions";

        private String apiKey;
        private String secret;
        private String authString;
        private String apiBaseURL;

        /// <summary>
        /// Creates a new instance of PasswordPing
        /// </summary>
        /// <param name="apiKey">your PasswordPing API key</param>
        /// <param name="apiSecret">your PasswordPing API secret</param>
        public PasswordPing(string apiKey, string apiSecret, string apiBaseURL = "https://api.passwordping.com/v1")
        {
            if (String.IsNullOrEmpty(apiKey))
                throw new ArgumentException("API Key cannot be null or empty");
            if (String.IsNullOrEmpty(apiSecret))
                throw new ArgumentException("API Secret cannot be null or empty");
            if (String.IsNullOrEmpty(apiBaseURL))
                throw new ArgumentException("API Base URL cannot be null or empty");

            this.apiKey = apiKey;
            this.secret = apiSecret;
            this.apiBaseURL = apiBaseURL;
            this.authString = "basic " + System.Convert.ToBase64String(Encoding.UTF8.GetBytes(apiKey + ":" + secret));
        }

        /// <summary>
        /// Checks whether the provided password is in the PasswordPing database of known, compromised passwords.
        /// @see <a href="https://www.passwordping.com/docs/passwords-api">https://www.passwordping.com/docs/passwords-api</a>
        /// </summary>
        /// <param name="password">The password to be checked</param>
        /// <returns>True if the password is a known, compromised password and should not be used</returns>
        public bool CheckPassword(string password)
        {
            bool revealedInExposure;
            int? relativeExposureFrequency;

            return CheckPassword(password, out revealedInExposure, out relativeExposureFrequency);
        }

        /// <summary>
        /// Checks whether the provided password is in the PasswordPing database of known, compromised passwords.
        /// @see <a href="https://www.passwordping.com/docs/passwords-api">https://www.passwordping.com/docs/passwords-api</a>
        /// </summary>
        /// <param name="password">The password to be checked</param>
        /// <param name="revealedInExposure">Out parameter.  Whether the password was exposed in a known data Exposure. If this value 
        /// is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user 
        /// password in a data breach or other Exposure.</param>
        /// <param name="relativeExposureFrequency">This is a gauge of how frequently the password has been seen in data breaches. 
        /// The value is simply the percent of data 
        /// breaches indexed by PasswordPing that have contained at least one instance of this password, i.e. if the value is 13, 
        /// that means 13% of the exposures that PasswordPing has indexed contained this password at least one time. This value can 
        /// be used to gauge how dangerous this password is by how common it is.</param>
        /// <returns>True if the password is a known, compromised password and should not be used</returns>
        public bool CheckPassword(string password, out bool revealedInExposure, out int? relativeExposureFrequency)
        {
            string md5 = Hashing.CalcMD5(password);
            string sha1 = Hashing.CalcSHA1(password);
            string sha256 = Hashing.CalcSHA256(password);

            String response = MakeRestCall(
                    apiBaseURL + PASSWORDS_API_PATH +
                        "?partial_md5=" + md5.Substring(0, 10) +
                        "&partial_sha1=" + sha1.Substring(0, 10) +
                        "&partial_sha256=" + sha256.Substring(0, 10),
                    "GET", null);

            if (response != "404")
            {
                dynamic responseObj = JObject.Parse(response);

                foreach (dynamic candidate in responseObj.candidates)
                {
                    if (candidate.md5 == md5 ||
                        candidate.sha1 == sha1 ||
                        candidate.sha256 == sha256)
                    {
                        revealedInExposure = candidate.revealedInExposure;
                        relativeExposureFrequency = candidate.relativeExposureFrequency;
                        return true;
                    }
                }
            }

            revealedInExposure = false;
            relativeExposureFrequency = null;
            return false;
        }

        /// <summary>
        /// Returns all of the credentials Exposures that have been found for a given username.
        /// @see <a href="https://www.passwordping.com/docs/exposures-api#get-exposures">https://www.passwordping.com/docs/exposures-api#get-exposures</a>
        /// </summary>
        /// <param name="username">The username or email address of the user to check</param>
        /// <returns>The response contains an array of exposure IDs for this user.  These IDs can be used with the GetExposureDetails call to get additional information about each Exposure.</returns>
        public ExposuresResponse GetExposuresForUser(string username)
        {
            ExposuresResponse result;

            String response = MakeRestCall(apiBaseURL + EXPOSURES_API_PATH + "?username=" + WebUtility.UrlEncode(username), "GET", null);

            if (response == "404")
            {
                // don't have this email in the DB - return empty response
                result = new ExposuresResponse()
                {
                    Count = 0,
                    Exposures = new string[0]
                };
            }
            else
            {
                // deserialize response
                result = JsonConvert.DeserializeObject<ExposuresResponse>(response);
            }

            return result;
        }

        public string MakeRestCall(string url, string method, string body)
        {
            WebClient client = new WebClient();

            client.Headers["authorization"] = this.authString;
            client.Headers["content-type"] = "application/json";
            var length = 0;
            if (body != null)
            {
                length = body.Count();
            }

            client.Headers["content-length"] = $"{length}";

            try
            {
                if (method == "POST" || method == "PUT" || method == "DELETE")
                {
                    return client.UploadString(url, body ?? string.Empty);
                }
                else
                {
                    return client.DownloadString(url);
                }
            }
            catch (WebException ex)
            {
                if (ex.Response != null && 
                    ex.Response.GetType().IsAssignableFrom(typeof(HttpWebResponse)) && 
                    ((HttpWebResponse)ex.Response).StatusCode == HttpStatusCode.NotFound)
                {
                    return "404";
                }
                else
                {
                    throw;
                }
            }
        }

        public string AddUserAlertSubscription(string email)
        {
            var hash = Hashing.CalcSHA256(email);
            var requestObject = JObject.FromObject(new
            {
                usernameHashes = new [] { hash }
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "POST",
                requestObject.ToString(Formatting.None)));
            if (responseObj.added == 1 || responseObj.alreadyExisted == 1)
            {
                return hash;
            }
            else return null;
        }

        public bool DeleteUserAlertSubscription(string credentialHash)
        {
            var requestObject = JObject.FromObject(new
            {
                usernameHashes = new [] { credentialHash }
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "DELETE",
                requestObject.ToString(Formatting.None)));
            if (responseObj.alreadyExisted == 1)
            {
                return true;
            }
            else return false;
        }
        
        public bool DeleteCredentialsAlertSubscription(string monitoredID)
        {
            var requestObject = JObject.FromObject(new
            {
                customData = monitoredID
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "DELETE",
                requestObject.ToString(Formatting.None)));
            if (responseObj.alreadyExisted == 1)
            {
                return true;
            }
            else return false;
        }          
        
        public bool DeleteUserAlertSubscriptionByCustomData(string customData)
        {
            var requestObject = JObject.FromObject(new
            {
                usernameCustomData = customData
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "DELETE",
                requestObject.ToString(Formatting.None)));
            if (responseObj.alreadyExisted == 1)
            {
                return true;
            }
            else return false;
        }        
        
        public bool DeleteCredentialsAlertSubscriptionByCustomData(string customData)
        {
            var requestObject = JObject.FromObject(new
            {
                customData = customData
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "DELETE",
                requestObject.ToString(Formatting.None)));
            if (responseObj.alreadyExisted == 1)
            {
                return true;
            }
            else return false;
        }            
        
        /// <summary>
        /// See if there is an existing Alert Subscription for the user
        /// @see <a href="https://www.passwordping.com/docs/exposures-api#get-exposures">https://www.passwordping.com/docs/exposures-api#get-exposures</a>
        /// </summary>
        /// <param name="username">The username or email address of the user to check</param>
        /// <returns>The response contains an array of exposure IDs for this user.  These IDs can be used with the GetExposureDetails call to get additional information about each Exposure.</returns>
        public string GetUserAlertSubscription(string email)
        {
            var hash = Hashing.CalcSHA256(email);
            var requestObject = JObject.FromObject(new
            {
                usernameHashes = new [] { hash }
            });
            dynamic responseObj = JObject.Parse(this.MakeRestCall(apiBaseURL + ALERTS_SERVICE_PATH, "GET",
                requestObject.ToString(Formatting.None)));
            if (responseObj.added == 1 || responseObj.alreadyExisted == 1)
            {
                return hash;
            }
            else return null;
        }        
    }
}
