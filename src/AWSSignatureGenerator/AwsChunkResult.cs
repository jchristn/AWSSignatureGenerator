namespace AWSSignatureGenerator
{
    using System.Collections.Generic;

    /// <summary>
    /// Represents a single chunk read from an aws-chunked encoded stream.
    /// </summary>
    public class AwsChunkResult
    {
        /// <summary>
        /// Chunk data bytes. Empty for the final chunk.
        /// </summary>
        public byte[] Data { get; set; } = null;

        /// <summary>
        /// Chunk signature from the chunk header.
        /// </summary>
        public string Signature { get; set; } = null;

        /// <summary>
        /// True if this is the final (zero-length) chunk.
        /// </summary>
        public bool IsFinal { get; set; } = false;

        /// <summary>
        /// Trailing headers, if present after the final chunk.
        /// </summary>
        public SortedDictionary<string, string> TrailerHeaders { get; set; } = null;

        /// <summary>
        /// Trailer signature, if present.
        /// </summary>
        public string TrailerSignature { get; set; } = null;
    }
}
