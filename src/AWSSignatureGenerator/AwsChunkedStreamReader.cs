namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    /// <summary>
    /// Reads an aws-chunked encoded stream and yields individual chunks with their signatures.
    ///
    /// Wire format:
    /// <code>
    /// &lt;hex-size&gt;;chunk-signature=&lt;signature&gt;\r\n
    /// &lt;chunk-data&gt;\r\n
    /// ...
    /// 0;chunk-signature=&lt;signature&gt;\r\n
    /// \r\n
    /// [optional trailing headers]\r\n
    /// \r\n
    /// 0;chunk-signature=&lt;trailer-signature&gt;\r\n
    /// \r\n
    /// </code>
    /// </summary>
    public class AwsChunkedStreamReader : IDisposable
    {
        #region Private-Members

        private readonly Stream _Stream;
        private bool _Disposed = false;
        private bool _FinalChunkRead = false;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate.
        /// </summary>
        /// <param name="stream">Input stream containing aws-chunked encoded data.</param>
        public AwsChunkedStreamReader(Stream stream)
        {
            _Stream = stream ?? throw new ArgumentNullException(nameof(stream));
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Read the next chunk from the stream.
        /// After the final data chunk is returned (IsFinal = true), call again to read
        /// trailing headers and trailer signature if present.
        /// Returns null when there is nothing left to read.
        /// </summary>
        /// <param name="token">Cancellation token.</param>
        /// <returns>Chunk result with data, signature, and whether this is the final chunk, or null if stream is exhausted.</returns>
        public async Task<AwsChunkResult> ReadNextChunkAsync(CancellationToken token = default)
        {
            if (_Disposed) throw new ObjectDisposedException(nameof(AwsChunkedStreamReader));

            string headerLine = await ReadLineAsync(token).ConfigureAwait(false);
            if (headerLine == null) return null;

            // After the final chunk, check for trailing headers
            if (_FinalChunkRead)
            {
                return ReadTrailerFromHeaderLine(headerLine, token);
            }

            // Parse: <hex-size>;chunk-signature=<signature>
            int semiIdx = headerLine.IndexOf(';');
            if (semiIdx < 0) return null;

            string hexSize = headerLine.Substring(0, semiIdx);
            int chunkSize = Convert.ToInt32(hexSize, 16);

            string sigPart = headerLine.Substring(semiIdx + 1);
            string signature = null;
            if (sigPart.StartsWith("chunk-signature="))
                signature = sigPart.Substring("chunk-signature=".Length);

            if (chunkSize == 0)
            {
                // Final chunk — consume the trailing \r\n
                await ReadLineAsync(token).ConfigureAwait(false);
                _FinalChunkRead = true;

                return new AwsChunkResult
                {
                    Data = Array.Empty<byte>(),
                    Signature = signature,
                    IsFinal = true
                };
            }

            // Read chunk data
            byte[] data = new byte[chunkSize];
            int totalRead = 0;
            while (totalRead < chunkSize)
            {
                token.ThrowIfCancellationRequested();
                int read = await _Stream.ReadAsync(data, totalRead, chunkSize - totalRead, token).ConfigureAwait(false);
                if (read == 0) throw new IOException("Unexpected end of stream while reading chunk data.");
                totalRead += read;
            }

            // Consume trailing \r\n after chunk data
            await ReadLineAsync(token).ConfigureAwait(false);

            return new AwsChunkResult
            {
                Data = data,
                Signature = signature,
                IsFinal = false
            };
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

        private AwsChunkResult ReadTrailerFromHeaderLine(string firstLine, CancellationToken token)
        {
            // firstLine could be a trailing header like "x-amz-checksum-crc32:<value>"
            // or it could be empty (no trailers)
            if (String.IsNullOrEmpty(firstLine)) return null;

            // Check if this is a trailer signature chunk: "0;chunk-signature=..."
            if (firstLine.StartsWith("0;chunk-signature="))
            {
                string trailerSig = firstLine.Substring("0;chunk-signature=".Length);
                return new AwsChunkResult
                {
                    Data = Array.Empty<byte>(),
                    Signature = null,
                    IsFinal = true,
                    TrailerSignature = trailerSig
                };
            }

            // Otherwise, read trailing headers
            SortedDictionary<string, string> trailerHeaders = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            // Parse the first trailing header line
            ParseTrailerHeader(firstLine, trailerHeaders);

            // Read remaining trailing header lines until empty line
            while (true)
            {
                string line = ReadLineAsync(token).ConfigureAwait(false).GetAwaiter().GetResult();
                if (String.IsNullOrEmpty(line)) break;
                ParseTrailerHeader(line, trailerHeaders);
            }

            // Now read the trailer signature chunk
            string trailerSigLine = ReadLineAsync(token).ConfigureAwait(false).GetAwaiter().GetResult();
            string trailerSignature = null;
            if (trailerSigLine != null && trailerSigLine.StartsWith("0;chunk-signature="))
            {
                trailerSignature = trailerSigLine.Substring("0;chunk-signature=".Length);
                // Consume trailing \r\n
                ReadLineAsync(token).ConfigureAwait(false).GetAwaiter().GetResult();
            }

            return new AwsChunkResult
            {
                Data = Array.Empty<byte>(),
                Signature = null,
                IsFinal = true,
                TrailerHeaders = trailerHeaders,
                TrailerSignature = trailerSignature
            };
        }

        private void ParseTrailerHeader(string line, SortedDictionary<string, string> headers)
        {
            int colonIdx = line.IndexOf(':');
            if (colonIdx > 0)
            {
                string key = line.Substring(0, colonIdx).Trim();
                string val = line.Substring(colonIdx + 1).Trim();
                headers[key] = val;
            }
        }

        private async Task<string> ReadLineAsync(CancellationToken token)
        {
            StringBuilder sb = new StringBuilder();
            byte[] buf = new byte[1];
            bool prevCr = false;

            while (true)
            {
                token.ThrowIfCancellationRequested();
                int read = await _Stream.ReadAsync(buf, 0, 1, token).ConfigureAwait(false);
                if (read == 0)
                {
                    return sb.Length > 0 ? sb.ToString() : null;
                }

                char c = (char)buf[0];
                if (c == '\r')
                {
                    prevCr = true;
                    continue;
                }
                if (c == '\n' && prevCr)
                {
                    return sb.ToString();
                }
                if (prevCr)
                {
                    sb.Append('\r');
                    prevCr = false;
                }
                sb.Append(c);
            }
        }

        #endregion
    }
}
