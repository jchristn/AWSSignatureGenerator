namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Computes and validates AWS V4 streaming (chunked) signatures.
    /// Each chunk's signature is chained from the previous signature (or the seed signature for the first chunk).
    /// </summary>
    public class V4ChunkSigner : IDisposable
    {
        #region Public-Members

        #endregion

        #region Private-Members

        private readonly string _Timestamp;
        private readonly string _Scope;
        private readonly byte[] _SigningKey;
        private string _PreviousSignature;
        private bool _Disposed = false;

        private static readonly string _EmptySha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate.
        /// </summary>
        /// <param name="timestamp">Request timestamp in yyyyMMddTHHmmssZ format.</param>
        /// <param name="region">AWS region.</param>
        /// <param name="service">AWS service.</param>
        /// <param name="signingKey">Derived signing key bytes from V4SignatureResult.SigningKeyBytes.</param>
        /// <param name="seedSignature">Seed signature from the Authorization header.</param>
        public V4ChunkSigner(
            string timestamp,
            string region,
            string service,
            byte[] signingKey,
            string seedSignature)
        {
            if (String.IsNullOrEmpty(timestamp)) throw new ArgumentNullException(nameof(timestamp));
            if (String.IsNullOrEmpty(region)) throw new ArgumentNullException(nameof(region));
            if (String.IsNullOrEmpty(service)) throw new ArgumentNullException(nameof(service));
            if (signingKey == null || signingKey.Length == 0) throw new ArgumentNullException(nameof(signingKey));
            if (String.IsNullOrEmpty(seedSignature)) throw new ArgumentNullException(nameof(seedSignature));

            _Timestamp = timestamp;
            _Scope = timestamp.Substring(0, 8) + "/" + region + "/" + service + "/aws4_request";
            _SigningKey = signingKey;
            _PreviousSignature = seedSignature;
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Compute the expected signature for the next chunk.
        /// Call this for each chunk in order, including the final zero-length chunk.
        /// This advances internal state (the previous signature is updated).
        /// </summary>
        /// <param name="chunkData">Chunk data bytes. Empty or null for the final chunk.</param>
        /// <returns>Expected hex signature for this chunk.</returns>
        public string ComputeChunkSignature(byte[] chunkData)
        {
            string chunkHash;
            if (chunkData == null || chunkData.Length == 0)
                chunkHash = _EmptySha256Hash;
            else
                chunkHash = BytesToHexString(Sha256(chunkData)).ToLower();

            string stringToSign =
                "AWS4-HMAC-SHA256-PAYLOAD\n" +
                _Timestamp + "\n" +
                _Scope + "\n" +
                _PreviousSignature + "\n" +
                _EmptySha256Hash + "\n" +
                chunkHash;

            string signature = BytesToHexString(HmacSha256(_SigningKey, Encoding.UTF8.GetBytes(stringToSign))).ToLower();
            _PreviousSignature = signature;
            return signature;
        }

        /// <summary>
        /// Validate a chunk's signature.
        /// This advances internal state (the previous signature is updated on success).
        /// </summary>
        /// <param name="chunkData">Chunk data bytes. Empty or null for the final chunk.</param>
        /// <param name="providedSignature">Signature from the chunk header.</param>
        /// <returns>True if signature matches.</returns>
        public bool ValidateChunk(byte[] chunkData, string providedSignature)
        {
            string expected = ComputeChunkSignature(chunkData);
            return String.Equals(expected, providedSignature, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Compute the expected signature for the trailing headers.
        /// Call this after the final zero-length chunk has been processed.
        /// This advances internal state.
        /// </summary>
        /// <param name="trailerHeaders">Trailing headers as key-value pairs, sorted by key.</param>
        /// <returns>Expected hex signature for the trailer.</returns>
        public string ComputeTrailerSignature(SortedDictionary<string, string> trailerHeaders)
        {
            if (trailerHeaders == null) throw new ArgumentNullException(nameof(trailerHeaders));

            StringBuilder sb = new StringBuilder();
            foreach (KeyValuePair<string, string> kvp in trailerHeaders)
            {
                sb.Append(kvp.Key.ToLower());
                sb.Append(":");
                sb.Append(kvp.Value.Trim());
                sb.Append("\n");
            }

            string trailingHeadersHash = BytesToHexString(Sha256(Encoding.UTF8.GetBytes(sb.ToString()))).ToLower();

            string stringToSign =
                "AWS4-HMAC-SHA256-TRAILER\n" +
                _Timestamp + "\n" +
                _Scope + "\n" +
                _PreviousSignature + "\n" +
                trailingHeadersHash;

            string signature = BytesToHexString(HmacSha256(_SigningKey, Encoding.UTF8.GetBytes(stringToSign))).ToLower();
            _PreviousSignature = signature;
            return signature;
        }

        /// <summary>
        /// Validate the trailer signature.
        /// Call this after the final zero-length chunk has been processed.
        /// </summary>
        /// <param name="trailerHeaders">Trailing headers as key-value pairs, sorted by key.</param>
        /// <param name="providedSignature">Signature from the trailer chunk.</param>
        /// <returns>True if signature matches.</returns>
        public bool ValidateTrailer(SortedDictionary<string, string> trailerHeaders, string providedSignature)
        {
            string expected = ComputeTrailerSignature(trailerHeaders);
            return String.Equals(expected, providedSignature, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">Disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_Disposed)
            {
                _Disposed = true;
            }
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region Private-Methods

        private byte[] Sha256(byte[] bytes)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
        }

        private byte[] HmacSha256(byte[] key, byte[] bytes)
        {
            using (HMACSHA256 hash = new HMACSHA256(key))
            {
                return hash.ComputeHash(bytes);
            }
        }

        private string BytesToHexString(byte[] bytes)
        {
            return BitConverter.ToString(bytes).Replace("-", "");
        }

        #endregion
    }
}
