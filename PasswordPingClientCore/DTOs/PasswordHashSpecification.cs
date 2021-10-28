using System;
using PasswordPingClientCore.Enums;

namespace PasswordPingClientCore.DTOs
{ 
    /// <summary>
    /// Specifications for a specific password hash - used internally by the Accounts API call
    /// </summary>
    class PasswordHashSpecification
    {
        /// <summary>
        /// The hash algorithm for this password specification
        /// </summary>
        public PasswordType HashType { get; set; }

        /// <summary>
        /// The salt value to use for this password, if any
        /// </summary>
        public String Salt { get; set; }
    }
}
