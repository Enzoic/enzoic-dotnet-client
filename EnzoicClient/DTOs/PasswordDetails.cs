using System;
using EnzoicClient.Enums;

namespace EnzoicClient
{
    /// <summary>
    /// The details for a specific user password.  
    /// </summary>
    public class PasswordDetails
    {
        /// <summary>
        /// The hash type the Password field contains.  Whenever possible, this will be PasswordType.Plaintext, but in the event
        /// Enzoic does not have a cracked plaintext equivalent for the password which was found, this will instead be the raw
        /// hash type that was found.  In this case, the Password field will contain a hash rather than a plaintext value and the Salt
        /// field may contain the salt value for the hash, if this is a hash type that employs a salt.
        /// </summary>
        public PasswordType HashType { get; set; }

        /// <summary>
        /// The password for this user.  Whenever possible, this will be PasswordType.Plaintext, but in the event
        /// Enzoic does not have a cracked plaintext equivalent for the password which was found, this will instead be the raw
        /// hash that was found.  This is provided so that you can hash a plaintext password into the same format and compare
        /// to see if they are equal.
        /// </summary>
        public string Password { get; set; }
        
        /// <summary>
        /// The salt for the provided password hash, when appropriate.  Whenever possible, this will be PasswordType.Plaintext, but in the event
        /// Enzoic does not have a cracked plaintext equivalent for the password which was found, the raw
        /// hash that was found will be returned.  For hash types where a salt is employed, this is the salt value which should be used.
        /// </summary>
        public string Salt { get; set; }
        
        /// <summary>
        /// An array of Exposure IDs. The IDs can be used with the GetExposureDetails call to retrieve additional info on each exposure.
        /// </summary>
        public string[] Exposures { get; set; }
    }
}
