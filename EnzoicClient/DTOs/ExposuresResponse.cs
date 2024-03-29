﻿using System;

namespace EnzoicClient
{
    /// <summary>
    /// Response object for the Enzoic.GetExposuresForUser method
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
}
