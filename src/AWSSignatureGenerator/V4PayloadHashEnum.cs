using System;
using System.Collections.Generic;
using System.Text;

namespace AWSSignatureGenerator
{
    /// <summary>
    /// V4 payload hash.
    /// </summary>
    public enum V4PayloadHashEnum
    {
        /// <summary>
        /// Streaming payload.
        /// </summary>
        IsStreaming,
        /// <summary>
        /// Unsigned payload.
        /// </summary>
        Unsigned,
        /// <summary>
        /// Signed payload.
        /// </summary>
        Signed
    }
}
