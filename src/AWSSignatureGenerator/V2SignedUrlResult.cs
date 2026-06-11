namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Specialized;
    using System.Text;

    /// <summary>
    /// AWS Signature Version 2 result for Amazon S3 signed URLs.
    /// </summary>
    public class V2SignedUrlResult : IDisposable
    {
        #region Public-Members

        /// <summary>
        /// AWS access key ID.
        /// </summary>
        public string AccessKey
        {
            get
            {
                return _AccessKey;
            }
        }

        /// <summary>
        /// AWS secret access key.
        /// </summary>
        public string SecretKey
        {
            get
            {
                return _SecretKey;
            }
        }

        /// <summary>
        /// HTTP method used for the signed URL.
        /// </summary>
        public string HttpMethod
        {
            get
            {
                return _HttpMethod;
            }
        }

        /// <summary>
        /// Original full URL before signing.
        /// </summary>
        public string FullUrl
        {
            get
            {
                return _FullUrl;
            }
        }

        /// <summary>
        /// URL scheme.
        /// </summary>
        public string Protocol
        {
            get
            {
                return _Uri.Scheme;
            }
        }

        /// <summary>
        /// URL port.
        /// </summary>
        public int Port
        {
            get
            {
                return _Uri.Port;
            }
        }

        /// <summary>
        /// URL host name.
        /// </summary>
        public string Hostname
        {
            get
            {
                return _Uri.Host;
            }
        }

        /// <summary>
        /// Raw URL path.
        /// </summary>
        public string Path
        {
            get
            {
                return _RawPath;
            }
        }

        /// <summary>
        /// Raw URL query string, including the leading question mark when present.
        /// </summary>
        public string Querystring
        {
            get
            {
                return _RawQuerystring;
            }
        }

        /// <summary>
        /// Parsed query string elements from the original URL.
        /// </summary>
        public NameValueCollection QueryElements
        {
            get
            {
                return V2S3Canonicalizer.ParseQueryElements(_RawQuerystring);
            }
        }

        /// <summary>
        /// Request headers that must be supplied by the signed URL consumer when signed.
        /// </summary>
        public NameValueCollection Headers
        {
            get
            {
                return _Headers;
            }
        }

        /// <summary>
        /// Expiration time as Unix epoch seconds.
        /// </summary>
        public long Expires
        {
            get
            {
                return _Expires;
            }
        }

        /// <summary>
        /// Expiration time as a UTC DateTimeOffset.
        /// </summary>
        public DateTimeOffset ExpiresAt
        {
            get
            {
                return DateTimeOffset.FromUnixTimeSeconds(_Expires);
            }
        }

        /// <summary>
        /// Content-MD5 header value used in the string to sign, or an empty string when absent.
        /// </summary>
        public string ContentMd5
        {
            get
            {
                return V2S3Canonicalizer.GetHeaderValue(_Headers, "Content-MD5");
            }
        }

        /// <summary>
        /// Content-Type header value used in the string to sign, or an empty string when absent.
        /// </summary>
        public string ContentType
        {
            get
            {
                return V2S3Canonicalizer.GetHeaderValue(_Headers, "Content-Type");
            }
        }

        /// <summary>
        /// Canonicalized x-amz-* headers used in the string to sign.
        /// </summary>
        public string CanonicalizedAmzHeaders
        {
            get
            {
                return V2S3Canonicalizer.CanonicalizeAmzHeaders(_Headers);
            }
        }

        /// <summary>
        /// Canonicalized S3 resource used in the string to sign.
        /// </summary>
        public string CanonicalizedResource
        {
            get
            {
                return V2S3Canonicalizer.CanonicalizeResource(_Uri, _RawPath, _RawQuerystring, _BucketName);
            }
        }

        /// <summary>
        /// S3 Signature Version 2 string to sign.
        /// </summary>
        public string StringToSign
        {
            get
            {
                return HttpMethod + "\n"
                    + ContentMd5 + "\n"
                    + ContentType + "\n"
                    + Expires.ToString() + "\n"
                    + CanonicalizedAmzHeaders
                    + CanonicalizedResource;
            }
        }

        /// <summary>
        /// Base64 HMAC-SHA1 signature.
        /// </summary>
        public string Signature
        {
            get
            {
                return V2S3Canonicalizer.SignHmacSha1Base64(SecretKey, StringToSign);
            }
        }

        /// <summary>
        /// RFC 3986 encoded signature value for use in the query string.
        /// </summary>
        public string EncodedSignature
        {
            get
            {
                return V2S3Canonicalizer.UriEncode(Signature);
            }
        }

        /// <summary>
        /// Signed URL containing AWSAccessKeyId, Expires, and Signature query parameters.
        /// </summary>
        public string SignedUrl
        {
            get
            {
                string separator = String.IsNullOrEmpty(_RawQuerystring) ? "?" : "&";
                return FullUrl
                    + separator
                    + "AWSAccessKeyId=" + V2S3Canonicalizer.UriEncode(AccessKey)
                    + "&Expires=" + Expires.ToString()
                    + "&Signature=" + EncodedSignature;
            }
        }

        #endregion

        #region Private-Members

        private readonly string _AccessKey = null;
        private readonly string _SecretKey = null;
        private readonly string _HttpMethod = null;
        private readonly string _FullUrl = null;
        private readonly string _BucketName = null;
        private readonly Uri _Uri = null;
        private readonly string _RawPath = "/";
        private readonly string _RawQuerystring = "";
        private readonly NameValueCollection _Headers = null;
        private readonly long _Expires = 0;
        private bool _Disposed = false;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate an S3 Signature Version 2 signed URL result.
        /// </summary>
        /// <param name="httpMethod">HTTP method.</param>
        /// <param name="fullUrl">Full request URL before signing.</param>
        /// <param name="accessKey">AWS access key ID.</param>
        /// <param name="secretKey">AWS secret access key.</param>
        /// <param name="expires">Expiration time as Unix epoch seconds. Must be greater than zero.</param>
        /// <param name="headers">Optional headers that participate in the signature.</param>
        /// <param name="bucketName">Optional explicit S3 bucket name for custom endpoints and CNAMEs.</param>
        /// <exception cref="ArgumentNullException">Thrown when a required string argument is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when expires is less than one.</exception>
        /// <exception cref="ArgumentException">Thrown when the URL is invalid or already contains SigV2 auth query parameters.</exception>
        public V2SignedUrlResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            long expires,
            NameValueCollection headers = null,
            string bucketName = null)
        {
            if (String.IsNullOrEmpty(httpMethod)) throw new ArgumentNullException(nameof(httpMethod));
            if (String.IsNullOrEmpty(fullUrl)) throw new ArgumentNullException(nameof(fullUrl));
            if (String.IsNullOrEmpty(accessKey)) throw new ArgumentNullException(nameof(accessKey));
            if (String.IsNullOrEmpty(secretKey)) throw new ArgumentNullException(nameof(secretKey));
            if (expires < 1) throw new ArgumentOutOfRangeException(nameof(expires), "Expiration time must be greater than zero.");

            Uri parsedUri;
            if (!Uri.TryCreate(fullUrl, UriKind.Absolute, out parsedUri))
            {
                throw new ArgumentException("The supplied full URL is not an absolute URI: " + fullUrl, nameof(fullUrl));
            }

            string rawPath;
            string rawQuerystring;
            V2S3Canonicalizer.ParseRawPathAndQuerystring(fullUrl, out rawPath, out rawQuerystring);
            ValidateNoExistingAuthQueryParameters(rawQuerystring);

            _HttpMethod = httpMethod.ToUpperInvariant();
            _FullUrl = fullUrl;
            _AccessKey = accessKey;
            _SecretKey = secretKey;
            _Headers = V2S3Canonicalizer.NormalizeHeaders(headers);
            _BucketName = bucketName;
            _Uri = parsedUri;
            _RawPath = rawPath;
            _RawQuerystring = rawQuerystring;
            _Expires = expires;
        }

        /// <summary>
        /// Instantiate an S3 Signature Version 2 signed URL result.
        /// </summary>
        /// <param name="httpMethod">HTTP method.</param>
        /// <param name="fullUrl">Full request URL before signing.</param>
        /// <param name="accessKey">AWS access key ID.</param>
        /// <param name="secretKey">AWS secret access key.</param>
        /// <param name="expiresAt">Expiration time.</param>
        /// <param name="headers">Optional headers that participate in the signature.</param>
        /// <param name="bucketName">Optional explicit S3 bucket name for custom endpoints and CNAMEs.</param>
        /// <exception cref="ArgumentNullException">Thrown when a required string argument is null or empty.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Thrown when expiresAt converts to a value less than one.</exception>
        /// <exception cref="ArgumentException">Thrown when the URL is invalid or already contains SigV2 auth query parameters.</exception>
        public V2SignedUrlResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            DateTimeOffset expiresAt,
            NameValueCollection headers = null,
            string bucketName = null)
            : this(httpMethod, fullUrl, accessKey, secretKey, expiresAt.ToUnixTimeSeconds(), headers, bucketName)
        {
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Human-readable representation of the V2 signed URL result.
        /// </summary>
        /// <returns>Diagnostic string containing canonical fields and signed URL output.</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("V2 Signed URL Result").Append(Environment.NewLine);
            builder.Append("--------------------").Append(Environment.NewLine);
            builder.Append("Access key              : ").Append(AccessKey).Append(Environment.NewLine);
            builder.Append("HTTP method             : ").Append(HttpMethod).Append(Environment.NewLine);
            builder.Append("Full URL                : ").Append(FullUrl).Append(Environment.NewLine);
            builder.Append("Expires                 : ").Append(Expires).Append(Environment.NewLine);
            builder.Append("Canonicalized resource  : ").Append(CanonicalizedResource).Append(Environment.NewLine);
            builder.Append("String to sign          : ").Append(Environment.NewLine).Append("[start]").Append(StringToSign).Append("[end]").Append(Environment.NewLine);
            builder.Append("Signature               : ").Append(Signature).Append(Environment.NewLine);
            builder.Append("Encoded signature       : ").Append(EncodedSignature).Append(Environment.NewLine);
            builder.Append("Signed URL              : ").Append(SignedUrl).Append(Environment.NewLine);
            return builder.ToString();
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">True when called from Dispose.</param>
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

        private static void ValidateNoExistingAuthQueryParameters(string rawQuerystring)
        {
            if (V2S3Canonicalizer.HasQueryParameter(rawQuerystring, "AWSAccessKeyId"))
            {
                throw new ArgumentException("The supplied URL already contains AWSAccessKeyId and cannot be signed again.", nameof(rawQuerystring));
            }

            if (V2S3Canonicalizer.HasQueryParameter(rawQuerystring, "Expires"))
            {
                throw new ArgumentException("The supplied URL already contains Expires and cannot be signed again.", nameof(rawQuerystring));
            }

            if (V2S3Canonicalizer.HasQueryParameter(rawQuerystring, "Signature"))
            {
                throw new ArgumentException("The supplied URL already contains Signature and cannot be signed again.", nameof(rawQuerystring));
            }
        }

        #endregion
    }
}
