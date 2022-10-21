using System;

namespace EnzoicClient
{
    /// <summary>
    /// Information about all of the passwords Enzoic has for a given user  
    /// </summary>
    public class UserPasswords
    {
        /// <summary>
        /// The last time a new exposure/breach was found containing this user
        /// </summary>
        public DateTime LastBreachDate { get; set; }

        // <summary>
        // An array of PasswordDetails objects containing the plaintext or hashed passwords Enzoic has for this user
        // </summary>
        public PasswordDetails[] Passwords { get; set; }
    }
}
