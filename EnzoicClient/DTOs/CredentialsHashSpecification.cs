using System;
using EnzoicClient.Enums;

namespace EnzoicClient.DTOs
{ 
    /// <summary>
    /// Specifications for a specific password hash - used internally by the Accounts API call
    /// </summary>
    class CredentialsHashSpecification
    {
        /// <summary>
        /// The hash algorithm for this password specification
        /// </summary>
        public PasswordType HashType { get; set; }

        /// <summary>
        /// The salt value to use for this password, if any
        /// </summary>
        public String Salt { get; set; }
        
        /// <summary>
        /// The Argon2 credentials hash for this set of credentials.
        /// </summary>
        public String CredentialsHash { get; set; }
    }
}