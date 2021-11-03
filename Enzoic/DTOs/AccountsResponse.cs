using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EnzoicClient.DTOs
{
    /// <summary>
    /// Response object for Accounts API call - internal use only
    /// </summary>
    class AccountsResponse
    {
        /// <summary>
        /// The salt value to use for credentials hashes for this account
        /// </summary>
        public String Salt { get; set; }

        /// <summary>
        /// The list of password hashes required to be calculated when checking credentials for this account
        /// </summary>
        public PasswordHashSpecification[] PasswordHashesRequired { get; set; }

        /// <summary>
        /// The date of the last breach affecting this user.  Can be used to determine if any new breached credentials have
        /// been indexed since the last time a check was run for these credentials.
        /// </summary>
        public DateTime lastBreachDate { get; set; }
    }
}
