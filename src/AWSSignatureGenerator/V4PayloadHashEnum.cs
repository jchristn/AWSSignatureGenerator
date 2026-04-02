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
        /// Streaming unsigned payload (uses literal "STREAMING-UNSIGNED-PAYLOAD-TRAILER").
        /// </summary>
        IsStreaming,
        /// <summary>
        /// Unsigned payload (uses literal "UNSIGNED-PAYLOAD").
        /// </summary>
        Unsigned,
        /// <summary>
        /// Signed payload (computes SHA-256 of request body).
        /// </summary>
        Signed,
        /// <summary>
        /// Streaming signed payload without trailers (uses literal "STREAMING-AWS4-HMAC-SHA256-PAYLOAD").
        /// Used for AWSSDK 4.x chunked uploads without trailing checksums.
        /// </summary>
        StreamingSigned,
        /// <summary>
        /// Streaming signed payload with trailers (uses literal "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER").
        /// Used for AWSSDK 4.x chunked uploads with trailing checksums.
        /// </summary>
        StreamingSignedTrailer
    }
}
