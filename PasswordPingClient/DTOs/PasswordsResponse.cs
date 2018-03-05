using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PasswordPingClient.DTOs
{
    /// <summary>
    /// Response object for Passwords API call - internal use only
    /// </summary>
    class PasswordsResponse
    {
        /// <summary>
        /// Whether the password was exposed in a known data Exposure. If this value is false, the password was found in common 
        /// password cracking dictionaries, but has not been directly exposed as a user password in a data breach or other Exposure.
        /// </summary>
        public bool revealedInExposure { get; set; }

        /// <summary>
        /// This is a gauge of how frequently the password has been seen in data breaches. The value is simply the percent of data 
        /// breaches indexed by PasswordPing that have contained at least one instance of this password, i.e. if the value is 13, 
        /// that means 13% of the exposures that PasswordPing has indexed contained this password at least one time. This value can 
        /// be used to gauge how dangerous this password is by how common it is.
        /// </summary>
        public int? relativeExposureFrequency { get; set; }
    }
}
