namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Specialized;
    using System.Text;

    /// <summary>
    /// AWS Signature Version 2 result for Amazon S3 REST Authorization header signing.
    /// </summary>
    public class V2SignatureResult : IDisposable
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
        /// HTTP method used for the request.
        /// </summary>
        public string HttpMethod
        {
            get
            {
                return _HttpMethod;
            }
        }

        /// <summary>
        /// Full request URL.
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
        /// Parsed query string elements.
        /// </summary>
        public NameValueCollection QueryElements
        {
            get
            {
                return V2S3Canonicalizer.ParseQueryElements(_RawQuerystring);
            }
        }

        /// <summary>
        /// Request headers.
        /// </summary>
        public NameValueCollection Headers
        {
            get
            {
                return _Headers;
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
        /// Date header value, or an empty string when absent.
        /// </summary>
        public string Date
        {
            get
            {
                return V2S3Canonicalizer.GetHeaderValue(_Headers, "Date");
            }
        }

        /// <summary>
        /// Date element used in the string to sign. Empty when an x-amz-date header is present.
        /// </summary>
        public string DateElement
        {
            get
            {
                if (V2S3Canonicalizer.HasAmzDateHeader(_Headers))
                {
                    return "";
                }

                return Date;
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
                    + DateElement + "\n"
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
        /// Complete S3 Signature Version 2 Authorization header value.
        /// </summary>
        public string AuthorizationHeader
        {
            get
            {
                return "AWS " + AccessKey + ":" + Signature;
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
        private bool _Disposed = false;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate an S3 Signature Version 2 header signing result.
        /// </summary>
        /// <param name="httpMethod">HTTP method.</param>
        /// <param name="fullUrl">Full request URL.</param>
        /// <param name="accessKey">AWS access key ID.</param>
        /// <param name="secretKey">AWS secret access key.</param>
        /// <param name="headers">Request headers. Must include Date or x-amz-date for header signing.</param>
        /// <param name="bucketName">Optional explicit S3 bucket name for custom endpoints and CNAMEs.</param>
        /// <exception cref="ArgumentNullException">Thrown when a required string argument is null or empty.</exception>
        /// <exception cref="ArgumentException">Thrown when the URL is invalid or the request lacks Date and x-amz-date headers.</exception>
        public V2SignatureResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            NameValueCollection headers,
            string bucketName = null)
        {
            if (String.IsNullOrEmpty(httpMethod)) throw new ArgumentNullException(nameof(httpMethod));
            if (String.IsNullOrEmpty(fullUrl)) throw new ArgumentNullException(nameof(fullUrl));
            if (String.IsNullOrEmpty(accessKey)) throw new ArgumentNullException(nameof(accessKey));
            if (String.IsNullOrEmpty(secretKey)) throw new ArgumentNullException(nameof(secretKey));

            Uri parsedUri;
            if (!Uri.TryCreate(fullUrl, UriKind.Absolute, out parsedUri))
            {
                throw new ArgumentException("The supplied full URL is not an absolute URI: " + fullUrl, nameof(fullUrl));
            }

            NameValueCollection normalizedHeaders = V2S3Canonicalizer.NormalizeHeaders(headers);
            bool hasDate = !String.IsNullOrEmpty(V2S3Canonicalizer.GetHeaderValue(normalizedHeaders, "Date"));
            bool hasAmzDate = V2S3Canonicalizer.HasAmzDateHeader(normalizedHeaders);

            if (!hasDate && !hasAmzDate)
            {
                throw new ArgumentException("S3 Signature Version 2 header signing requires either a Date header or an x-amz-date header.", nameof(headers));
            }

            _HttpMethod = httpMethod.ToUpperInvariant();
            _FullUrl = fullUrl;
            _AccessKey = accessKey;
            _SecretKey = secretKey;
            _Headers = normalizedHeaders;
            _BucketName = bucketName;
            _Uri = parsedUri;

            string rawPath;
            string rawQuerystring;
            V2S3Canonicalizer.ParseRawPathAndQuerystring(fullUrl, out rawPath, out rawQuerystring);
            _RawPath = rawPath;
            _RawQuerystring = rawQuerystring;
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Human-readable representation of the V2 signature result.
        /// </summary>
        /// <returns>Diagnostic string containing canonical fields and signature output.</returns>
        public override string ToString()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append("V2 Signature Result").Append(Environment.NewLine);
            builder.Append("-------------------").Append(Environment.NewLine);
            builder.Append("Access key              : ").Append(AccessKey).Append(Environment.NewLine);
            builder.Append("HTTP method             : ").Append(HttpMethod).Append(Environment.NewLine);
            builder.Append("Full URL                : ").Append(FullUrl).Append(Environment.NewLine);
            builder.Append("Protocol                : ").Append(Protocol).Append(Environment.NewLine);
            builder.Append("Port                    : ").Append(Port).Append(Environment.NewLine);
            builder.Append("Hostname                : ").Append(Hostname).Append(Environment.NewLine);
            builder.Append("Path                    : ").Append(Path).Append(Environment.NewLine);
            builder.Append("Querystring             : ").Append(Querystring).Append(Environment.NewLine);
            builder.Append("Content-MD5             : ").Append(ContentMd5).Append(Environment.NewLine);
            builder.Append("Content-Type            : ").Append(ContentType).Append(Environment.NewLine);
            builder.Append("Date                    : ").Append(Date).Append(Environment.NewLine);
            builder.Append("Date element            : ").Append(DateElement).Append(Environment.NewLine);
            builder.Append("Canonicalized amz hdrs  : ").Append(Environment.NewLine).Append("[start]").Append(CanonicalizedAmzHeaders).Append("[end]").Append(Environment.NewLine);
            builder.Append("Canonicalized resource  : ").Append(CanonicalizedResource).Append(Environment.NewLine);
            builder.Append("String to sign          : ").Append(Environment.NewLine).Append("[start]").Append(StringToSign).Append("[end]").Append(Environment.NewLine);
            builder.Append("Signature               : ").Append(Signature).Append(Environment.NewLine);
            builder.Append("Authorization header    : ").Append(AuthorizationHeader).Append(Environment.NewLine);
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
    }
}
