using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EnzoicClient
{
    /// <summary>
    /// The detailed information about a given credentials Exposure.  
    /// </summary>
    public class ExposureDetails
    {
        /// <summary>
        /// The ID of the exposure
        /// </summary>
        public String ID { get; set; }

        /// <summary>
        /// Title of the exposure - for breaches, the domain of the origin site
        /// </summary>
        public String Title { get; set; }

        /// <summary>
        /// The number of credentials found in the exposure
        /// </summary>
        public int Entries { get; set; }

        /// <summary>
        /// The date the exposure occurred, as much as is known. The value is as follows:
        /// *      - null if the date is not known
        /// *      - Month and day set to December 31st, if only the year is known(e.g. "2015-12-31" if Exposure date was sometime in 2015)
        /// *      - Day set to the first of the month if only the month is known(e.g. "2015-06-01" if Exposure date was sometime in June 2015)
        /// *      - Otherwise, exact date if exact date is known, including time
        /// </summary>
        public DateTime? Date { get; set; }

        /// <summary>
        /// A category for the origin website, if the exposure was a data breach.
        /// </summary>
        public String Category { get; set; }

        /// <summary>
        /// The format of the passwords in the Exposure, e.g. "Cleartext", "MD5", "BCrypt", etc.
        /// </summary>
        public String PasswordType { get; set; }

        /// <summary>
        /// The types of user data which were present in the Exposure, e.g. "Emails", "Passwords", "Physical Addresses", "Phone Numbers", etc.
        /// </summary>
        public String[] ExposedData { get; set; }

        /// <summary>
        /// The date the Exposure was found and added to the Enzoic database.
        /// </summary>
        public DateTime? DateAdded { get; set; }

        /// <summary>
        /// An array of URLs the data was found at. Only present for some types of Exposures, like when the source was a paste site.
        /// </summary>
        public String[] SourceURLs { get; set; }

        /// <summary>
        /// The number of unique email address domains in this Exposure. So, for instance, if the Exposure only contained "gmail.com" and "yahoo.com" email addresses, this number would be 2.
        /// </summary>
        public int DomainsAffected { get; set; }
    }
}
