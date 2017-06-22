# PasswordPing .NET Client Library

## TOC

This README covers the following topics:

- [Installation](#installation)
- [API Overview](#api-overview)
- [The PasswordPing constructor](#the-passwordping-constructor)
- [JavaDocs](#javadocs)

## Installation

The compiled library is available from NuGet:

### Nuget

```
Install-Package PasswordPing
```

## API Overview

Here's the API in a nutshell.

```cs
// Create a new PasswordPing instance - this is our primary interface for making API calls
PasswordPing passwordping = new PasswordPing("YOUR_API_KEY", "YOUR_API_SECRET");
 
// Check whether a password has been compromised
if (passwordping.CheckPassword("password-to-test")) {
    Console.WriteLine("Password is compromised");
}
else {
    Console.WriteLine("Password is not compromised");
}
 
// Check whether a specific set of credentials are compromised
if (passwordping.CheckCredentials("test@passwordping.com", "password-to-test")) {
    Console.WriteLine("Credentials are compromised");
}
else {
    Console.WriteLine("Credentials are not compromised");
}
 
// get all exposures for a given user
ExposuresResponse exposures = passwordping.GetExposuresForUser("test@passwordping.com");
Console.WriteLine(exposures.Count + " exposures found for test@passwordping.com");
 
// now get the full details for the first exposure returned in the exposures response
ExposureDetails details = passwordping.GetExposureDetails(exposures.Exposures[0]);
Console.WriteLine("First exposure for test@passwordping.com was " + details.Title);
```

More information in reference format can be found below.

## The PasswordPing constructor

The standard constructor takes the API key and secret you were issued on PasswordPing signup.

```cs
PasswordPing passwordping = new PasswordPing("YOUR_API_KEY", "YOUR_API_SECRET");
```

If you were instructed to use an alternate API endpoint, you may call the overloaded constructor and pass the base URL you were provided.

```cs
PasswordPing passwordping = new PasswordPing("YOUR_API_KEY", "YOUR_API_SECRET", "https://api-alt.passwordping.com/v1");
```

## ExposuresResponse

The PasswordPing.GetExposuresForUser method returns the response object below.

```cs
    /// <summary>
    /// Response object for the PasswordPing.GetExposuresForUser method
    /// </summary>
    public class ExposuresResponse
    {
        /// <summary>
        /// The number of items in the exposures array
        /// </summary>
        public int Count { get; set; }

        /// <summary>
        /// An array of Exposure IDs. The IDs can be used with the GetExposureDetails call to retrieve additional info on each exposure.
        /// </summary>
        public String[] Exposures { get; set; }
    }
```

## ExposureDetails

The PasswordPing.GetExposureDetails method returns the response object below.

```cs
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
        public DateTime Date { get; set; }

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
        /// The date the Exposure was found and added to the PasswordPing database.
        /// </summary>
        public DateTime DateAdded { get; set; }

        /// <summary>
        /// An array of URLs the data was found at. Only present for some types of Exposures, like when the source was a paste site.
        /// </summary>
        public String[] SourceURLs { get; set; }

        /// <summary>
        /// The number of unique email address domains in this Exposure. So, for instance, if the Exposure only contained "gmail.com" and "yahoo.com" email addresses, this number would be 2.
        /// </summary>
        public int DomainsAffected { get; set; }
    }
```

## License

This code is free to use under the terms of the MIT license.
