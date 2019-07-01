using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Net;
using EnzoicClient.Enums;
using EnzoicClient.Utilities;
using EnzoicClient.DTOs;

namespace EnzoicClient
{
    public class Enzoic
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
        /// Creates a new instance of Enzoic
        /// </summary>
        /// <param name="apiKey">your Enzoic API key</param>
        /// <param name="apiSecret">your Enzoic API secret</param>
        public Enzoic(string apiKey, string apiSecret, string apiBaseURL = "https://api.enzoic.com/v1")
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
        /// Checks whether the provided password is in the Enzoic database of known, compromised passwords.
        /// @see <a href="https://www.enzoic.com/docs/passwords-api">https://www.enzoic.com/docs/passwords-api</a>
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
        /// Checks whether the provided password is in the Enzoic database of known, compromised passwords.
        /// @see <a href="https://www.enzoic.com/docs/passwords-api">https://www.enzoic.com/docs/passwords-api</a>
        /// </summary>
        /// <param name="password">The password to be checked</param>
        /// <param name="revealedInExposure">Out parameter.  Whether the password was exposed in a known data Exposure. If this value 
        /// is false, the password was found in common password cracking dictionaries, but has not been directly exposed as a user 
        /// password in a data breach or other Exposure.</param>
        /// <param name="relativeExposureFrequency">This is a gauge of how frequently the password has been seen in data breaches. 
        /// The value is simply the percent of data 
        /// breaches indexed by Enzoic that have contained at least one instance of this password, i.e. if the value is 13, 
        /// that means 13% of the exposures that Enzoic has indexed contained this password at least one time. This value can 
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
        /// Calls the Enzoic CheckCredentials API in a secure fashion to check whether the provided username and password
        /// are known to be compromised.
        /// This call is made securely to the server - only a salted and hashed representation of the credentials are passed and
        /// the salt value is not passed along with it.
        /// @see <a href="https://www.enzoic.com/docs/credentials-api">https://www.enzoic.com/docs/credentials-api</a>
        /// </summary>
        /// <param name="username">the username to check - may be an email address or username</param>
        /// <param name="password">the password to check</param>
        /// <param name="lastCheckDate">(Optional) The timestamp for the last check you performed for this user.  If the date/time you provide 
        /// for the last check is greater than the timestamp Enzoic has for the last breach affecting this user, the check will 
        /// not be performed.This can be used to substantially increase performance.Can be set to null if no last check was performed 
        /// or the credentials have changed since.</param>
        /// <param name="excludeHashTypes">(Optional) An array of PasswordTypes to ignore when calculating hashes for the credentials check.  
        /// By excluding computationally expensive PasswordTypes, such as BCrypt, it is possible to balance the performance of this 
        /// call against security.Can be set to null if you don't wish to exclude any hash types.</param>
        /// <returns>true if the credentials are known to be compromised, false otherwise</returns>
        public bool CheckCredentials(string username, string password, DateTime? lastCheckDate = null, 
            PasswordType[] excludeHashTypes = null)
        {
            String response = MakeRestCall(
                    apiBaseURL + ACCOUNTS_API_PATH + "?username=" +
                            WebUtility.UrlEncode(Hashing.CalcSHA256(username)),
                    "GET", null);

            if (response == "404")
            {
                // this is all we needed to check for this - email wasn't even in the DB
                return false;
            }

            // deserialize response
            AccountsResponse accountsResponse = JsonConvert.DeserializeObject<AccountsResponse>(response);

            // see if the lastCheckDate was later than the lastBreachDate - if so bail out
            if (lastCheckDate.HasValue && lastCheckDate.Value >= accountsResponse.lastBreachDate)
            {
                return false;
            }

            int bcryptCount = 0;

            List<string> credentialHashes = new List<string>();
            StringBuilder queryString = new StringBuilder();
            foreach (PasswordHashSpecification hashSpec in accountsResponse.PasswordHashesRequired)
            {
                if (excludeHashTypes != null && excludeHashTypes.Contains(hashSpec.HashType))
                {
                    // this type is excluded
                    continue;
                }

                // bcrypt gets far too expensive for good response time if there are many of them to calculate.
                // some mostly garbage accounts have accumulated a number of them in our DB and if we happen to hit one it
                // kills performance, so short circuit out after at most 2 BCrypt hashes
                if (hashSpec.HashType != PasswordType.BCrypt || bcryptCount <= 2)
                {
                    if (hashSpec.HashType == PasswordType.BCrypt) bcryptCount++;

                    String credentialHash = CalcCredentialHash(username, password, accountsResponse.Salt, hashSpec);

                    if (credentialHash != null)
                    {
                        credentialHashes.Add(credentialHash);
                        if (queryString.Length == 0)
                            queryString.Append("?partialHashes=").Append(credentialHash.Substring(0, 10));
                        else
                            queryString.Append("&partialHashes=").Append(credentialHash.Substring(0, 10));
                    }
                }
            }

            if (queryString.Length > 0)
            {
                String credsResponse = MakeRestCall(
                        apiBaseURL + CREDENTIALS_API_PATH + queryString, "GET", null);

                if (credsResponse != "404")
                {
                    // loop through candidate hashes returned and see if we have a match with the exact hash
                    dynamic responseObj = JObject.Parse(credsResponse);

                    foreach (dynamic candidate in responseObj.candidateHashes)
                    {
                        if (credentialHashes.FirstOrDefault(hash => hash == candidate.ToString()) != null)
                        {
                            return true;
                        }
                    }

                }
            }

            return false;
        }

        /// <summary>
        /// Returns all of the credentials Exposures that have been found for a given username.
        /// @see <a href="https://www.enzoic.com/docs/exposures-api#get-exposures">https://www.enzoic.com/docs/exposures-api#get-exposures</a>
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

        /// <summary>
        /// Returns the detailed information for a credentials Exposure.
        /// @see <a href="https://www.enzoic.com/docs/exposures-api#get-exposure-details">https://www.enzoic.com/docs/exposures-api#get-exposure-details</a>
        /// </summary>
        /// <param name="exposureID">The ID of the Exposure</param>
        /// <returns>The response body contains the details of the Exposure or null if the Exposure ID could not be found.</returns>
        public ExposureDetails GetExposureDetails(string exposureID)
        {
            ExposureDetails result = null;

            String response = MakeRestCall(apiBaseURL + EXPOSURES_API_PATH + "?id=" + WebUtility.UrlEncode(exposureID), "GET", null);

            if (response != "404")
            {
                // deserialize response
                result = JsonConvert.DeserializeObject<ExposureDetails>(response);
            }

            return result;
        }

        private string MakeRestCall(string url, string method, string body)
        {
            WebClient client = new WebClient();

            client.Headers["authorization"] = this.authString;

            try
            {
                if (method == "POST" || method == "PUT")
                {
                    return client.UploadString(url, body);
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

        private String CalcCredentialHash(String username, String password, String salt, PasswordHashSpecification specification)
        {
            String passwordHash = Hashing.CalcPasswordHash(specification.HashType, password, specification.Salt);

            if (passwordHash != null)
            {
                String argon2Hash = Hashing.CalcArgon2(username + "$" + passwordHash, salt);

                String justHash = argon2Hash.Substring(argon2Hash.LastIndexOf('$') + 1);

                return Hashing.ToHexString(Hashing.DecodeBase64(justHash));
            }
            else
            {
                return null;
            }
        }
    }
}
