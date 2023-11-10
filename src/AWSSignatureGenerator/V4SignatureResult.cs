namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using System.Web;

    /// <summary>
    /// V4 signature result.
    /// </summary>
    public class V4SignatureResult : IDisposable
    {
        /*
         * Helpful reference links
         * 
         * https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
         * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
         * https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_aws-signing.html
         * https://docs.aws.amazon.com/IAM/latest/UserGuide/create-signed-request.html
         * 
         * Helpful source links
         * 
         * https://github.com/boto/botocore/blob/develop/botocore/auth.py
         * https://www.aloneguid.uk/posts/2021/02/aws-s3-auth-raw/
         * https://gist.github.com/yvanin/0bdf68c1139ad698519e
         * 
         */

        #region Public-Members

        /// <summary>
        /// Stream buffer size.
        /// </summary>
        public int StreamBufferSize
        {
            get
            {
                return _StreamBufferSize;
            }
            set
            {
                if (value < 1) throw new ArgumentOutOfRangeException(nameof(StreamBufferSize));
                _StreamBufferSize = value;
            }
        }

        /// <summary>
        /// Timestamp.
        /// </summary>
        public string Timestamp { get; set; } = DateTime.UtcNow.ToString(_AmazonTimestampFormatCompact);

        /// <summary>
        /// Access key.
        /// </summary>
        public string AccessKey { get; set; } = null;

        /// <summary>
        /// Secret key.
        /// </summary>
        public string SecretKey { get; set; } = null;

        /// <summary>
        /// AWS region.
        /// </summary>
        public string Region { get; set; } = null;

        /// <summary>
        /// AWS service.
        /// </summary>
        public string Service { get; set; } = "s3";

        /// <summary>
        /// Protocol.
        /// </summary>
        public string Protocol
        {
            get
            {
                return _Uri.Scheme;
            }
        }

        /// <summary>
        /// HTTP method.
        /// </summary>
        public string HttpMethod
        {
            get
            {
                return _HttpMethod;
            }
        }

        /// <summary>
        /// Full URL.
        /// </summary>
        public string FullUrl
        {
            get
            {
                return _FullUrl;
            }
        }

        /// <summary>
        /// Port.
        /// </summary>
        public int Port
        {
            get
            {
                return _Uri.Port;
            }
        }

        /// <summary>
        /// Hostname.
        /// </summary>
        public string Hostname
        {
            get
            {
                return _Uri.Host;
            }
        }

        /// <summary>
        /// Full URL without query.
        /// </summary>
        public string FullUrlWithoutQuery
        {
            get
            {
                if (!FullUrl.Contains("?")) return FullUrl;
                int idx = FullUrl.IndexOf("?");
                return FullUrl.Substring(0, idx);
            }
        }

        /// <summary>
        /// Path.
        /// </summary>
        public string Path
        {
            get
            {
                string ret = _Uri.PathAndQuery;
                if (!String.IsNullOrEmpty(ret))
                {
                    if (!ret.StartsWith("/")) ret = "/" + ret;
                    if (ret.Contains("?"))
                    {
                        int idx = ret.IndexOf("?");
                        ret = ret.Substring(0, idx);
                    }
                }
                return ret;
            }
        }

        /// <summary>
        /// Querystring.
        /// </summary>
        public string Querystring
        {
            get
            {
                return _Uri.Query;
            }
        }

        /// <summary>
        /// Querystring elements.
        /// </summary>
        public NameValueCollection QueryElements
        {
            get
            {
                NameValueCollection ret = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase);

                if (!String.IsNullOrEmpty(Querystring))
                {
                    string query = Querystring;
                    query = query.Replace("?", "");

                    string[] elements = query.Split('&');

                    foreach (string element in elements)
                    {
                        string key = element;
                        string val = null;

                        if (element.Contains("="))
                        {
                            int idx = element.IndexOf("=");
                            val = element.Substring((idx + 1), (element.Length - idx - 1));
                            key = element.Substring(0, idx);
                        }

                        ret.Add(key, val);
                    }
                }

                return ret;
            }
        }

        /// <summary>
        /// Host header.
        /// </summary>
        public string HostHeader
        {
            get
            {
                return Hostname + ":" + Port;
            }
        }

        /// <summary>
        /// Canonical URI.
        /// </summary>
        public string CanonicalUri
        {
            get
            {
                return Path;
            }
        }

        /// <summary>
        /// Canonical querystring.
        /// </summary>
        public string CanonicalQuerystring
        {
            get
            {
                string ret = "";

                if (QueryElements != null && QueryElements.AllKeys.Count() > 0)
                {
                    int added = 0;

                    for (int i = 0; i < QueryElements.AllKeys.Count(); i++)
                    {
                        string key = Uri.EscapeDataString(QueryElements.GetKey(i));
                        string[] vals = QueryElements.GetValues(i);

                        if (vals == null || vals.Length < 1)
                        {
                            if (added > 0) ret += "&";
                            ret += key + "=";
                            added++;
                        }
                        else
                        {
                            foreach (string val in vals)
                            {
                                if (added > 0) ret += "&";
                                ret += key + "=";
                                if (!String.IsNullOrEmpty(val)) ret += Uri.EscapeDataString(val);
                                added++;
                            }
                        }
                    }
                }

                return ret;
            }
        }

        /// <summary>
        /// Canonical headers.
        /// </summary>
        public string CanonicalHeaders
        {
            get
            {
                string ret = "";

                if (Headers != null && Headers.AllKeys.Count() > 0)
                {
                    for (int i = 0; i < Headers.AllKeys.Count(); i++)
                    {
                        string key = Headers.GetKey(i).ToLower();
                        string val = Headers.Get(key);
                        if (!String.IsNullOrEmpty(val)) val = val.Trim();
                        
                        if (!_HeaderIgnoreList.Contains(key))
                        {
                            ret += key + ":" + val + "\n";
                        }
                    }
                }

                return ret;
            }
        }

        /// <summary>
        /// Signed headers.
        /// </summary>
        public List<string> SignedHeaders
        {
            get
            {
                List<string> ret = new List<string>();

                if (Headers != null && Headers.AllKeys.Count() > 0)
                {
                    for (int i = 0; i < Headers.AllKeys.Count(); i++)
                    {
                        string key = Headers.GetKey(i).ToLower();

                        if (!_HeaderIgnoreList.Contains(key))
                        {
                            ret.Add(key);
                        }
                    }
                }

                return ret;
            }
        }

        /// <summary>
        /// Canonical request.
        /// </summary>
        public string CanonicalRequest
        {
            get
            {
                string ret = "";
                ret += HttpMethod + "\n";
                ret += CanonicalUri + "\n";
                ret += CanonicalQuerystring + "\n";
                ret += CanonicalHeaders + "\n";
                ret += string.Join(";", SignedHeaders) + "\n";
                ret += HashedPayload;
                return ret;
            }
        }

        /// <summary>
        /// String to sign.
        /// </summary>
        public string StringToSign
        {
            get
            {
                string ret = "";
                ret += "AWS4-HMAC-SHA256\n";
                ret += Timestamp + "\n";
                ret += Timestamp.Substring(0, 8) + "/" + Region + "/" + Service + "/aws4_request\n";
                ret += Convert.ToHexString(Sha256(Encoding.UTF8.GetBytes(CanonicalRequest))).ToLower();
                return ret;
            }
        }

        /// <summary>
        /// Headers.
        /// </summary>
        public NameValueCollection Headers { get; set; } = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase);

        /// <summary>
        /// Payload hashing method.
        /// </summary>
        public V4PayloadHashEnum PayloadHash { get; set; } = V4PayloadHashEnum.Signed;

        /// <summary>
        /// Hashed payload.
        /// </summary>
        public string HashedPayload
        {
            get
            {
                if (PayloadHash == V4PayloadHashEnum.Unsigned)
                {
                    return _ChecksumUnsignedPayload;
                }
                else if (PayloadHash == V4PayloadHashEnum.IsStreaming)
                {
                    return _ChecksumStreamingUnsigned;
                }
                else if (PayloadHash == V4PayloadHashEnum.Signed)
                {
                    if (_RequestBodyStream != null)
                    {
                        return Convert.ToHexString(Sha256(_RequestBodyStream)).ToLower();
                    }
                    else if (_RequestBodyBytes != null)
                    {
                        return Convert.ToHexString(Sha256(_RequestBodyBytes)).ToLower();
                    }
                    else if (_RequestBodyString != null)
                    {
                        return Convert.ToHexString(Sha256(Encoding.UTF8.GetBytes(_RequestBodyString))).ToLower();
                    }

                    return _EmptySha256Hash;
                }

                throw new ArgumentException("Unknown payload hashing value '" + PayloadHash.ToString() + "'.");
            }
        }

        /// <summary>
        /// Request body type.
        /// </summary>
        public Type RequestBodyType { get; set; } = null;

        /// <summary>
        /// Date key.
        /// </summary>
        public string DateKey
        {
            get
            {
                if (_DateKey != null) return Convert.ToHexString(_DateKey).ToLower();
                return null;
            }
        }

        /// <summary>
        /// Region key.
        /// </summary>
        public string RegionKey
        {
            get
            {
                if (_DateRegionKey != null) return Convert.ToHexString(_DateRegionKey).ToLower();
                return null;
            }
        }

        /// <summary>
        /// Service key.
        /// </summary>
        public string ServiceKey
        {
            get
            {
                if (_DateRegionServiceKey != null) return Convert.ToHexString(_DateRegionServiceKey).ToLower();
                return null;
            }
        }

        /// <summary>
        /// Signing key.
        /// </summary>
        public string SigningKey
        {
            get
            {
                if (_SigningKey != null) return Convert.ToHexString(_SigningKey).ToLower();
                return null;
            }
        }

        /// <summary>
        /// Signature.
        /// </summary>
        public string Signature
        {
            get
            {
                return Convert.ToHexString(
                    HmacSha256(
                        _SigningKey,
                        Encoding.UTF8.GetBytes(StringToSign)
                    )
                ).ToLower();
            }
        }

        /// <summary>
        /// Authorization header.
        /// </summary>
        public string AuthorizationHeader
        {
            get
            {
                string ret = "AWS4-HMAC-SHA256 ";

                ret += "Credential=" + AccessKey
                    + "/" + Timestamp.Substring(0, 8)
                    + "/" + Region
                    + "/" + Service
                    + "/aws4_request, ";

                ret += "SignedHeaders=" + string.Join(";", SignedHeaders) + ", ";
                ret += "Signature=" + Signature;

                return ret;
            }
        }

        #endregion

        #region Private-Members

        private int _StreamBufferSize = 1024 * 1024;
        private string _HttpMethod = "GET";
        private string _FullUrl = null;
        private Uri _Uri;

        private static string _EmptySha256Hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        private static string _AmazonTimestampFormatCompact = "yyyyMMddTHHmmssZ";
        private static string _ChecksumUnsignedPayload = "UNSIGNED-PAYLOAD";
        private static string _ChecksumStreamingUnsigned = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

        private static List<string> _HeaderIgnoreList = new List<string>
        {
            "expect",
            "user-agent",
            "x-amzn-trace-id"
        };

        private static List<string> _QueryElementsToInclude = new List<string>
        {
            "accelerate",
            "acl",
            "cors",
            "defaultObjectAcl",
            "location",
            "logging",
            "partNumber",
            "policy",
            "requestPayment",
            "torrent",
            "versioning",
            "versionId",
            "versions",
            "website",
            "uploads",
            "uploadId",
            "response-content-type",
            "response-content-language",
            "response-expires",
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "delete",
            "lifecycle",
            "tagging",
            "restore",
            "storageClass",
            "notification",
            "replication",
            "requestPayment",
            "analytics",
            "metrics",
            "inventory",
            "select",
            "select-type",
            "object-lock",
        };

        private Stream _RequestBodyStream = null;
        private byte[] _RequestBodyBytes = null;
        private string _RequestBodyString = null;

        private byte[] _DateKey = null;
        private byte[] _DateRegionKey = null;
        private byte[] _DateRegionServiceKey = null;
        private byte[] _SigningKey = null;

        private bool _Disposed = false;

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiate.
        /// </summary>
        /// <param name="timestamp">Timestamp of the form yyyyMMddTHHmmssZ.</param>
        /// <param name="httpMethod">HTTP method.</param>
        /// <param name="fullUrl">Full URL.</param>
        /// <param name="accessKey">Access key.</param>
        /// <param name="secretKey">Secret key.</param>
        /// <param name="region">Region.</param>
        /// <param name="service">Service.</param>
        /// <param name="headers">Request headers.</param>
        /// <param name="requestBody">Request body (Stream, byte[], or string).</param>
        /// <param name="payloadHashing">Payload hashing method.</param>
        public V4SignatureResult(
            string timestamp, 
            string httpMethod, 
            string fullUrl, 
            string accessKey, 
            string secretKey,
            string region,
            string service,
            NameValueCollection headers,
            object requestBody = null,
            V4PayloadHashEnum payloadHashing = V4PayloadHashEnum.Signed)
        {
            if (String.IsNullOrEmpty(timestamp)) throw new ArgumentNullException(nameof(timestamp));
            if (String.IsNullOrEmpty(httpMethod)) throw new ArgumentNullException(nameof(httpMethod));
            if (String.IsNullOrEmpty(fullUrl)) throw new ArgumentNullException(nameof(fullUrl));
            if (String.IsNullOrEmpty(accessKey)) throw new ArgumentNullException(nameof(accessKey));
            if (String.IsNullOrEmpty(secretKey)) throw new ArgumentNullException(nameof(secretKey));
            if (String.IsNullOrEmpty(region)) throw new ArgumentNullException(nameof(region));
            if (String.IsNullOrEmpty(service)) throw new ArgumentNullException(nameof(service));

            DateTime.ParseExact(timestamp, _AmazonTimestampFormatCompact, CultureInfo.InvariantCulture);

            Timestamp = timestamp;
            AccessKey = accessKey;
            SecretKey = secretKey;
            Headers = headers;
            Region = region;
            Service = service;
            PayloadHash = payloadHashing;

            if (headers != null && !headers.AllKeys.Contains("host"))
            {
                throw new ArgumentException("Supplied headers does not include 'host' header.");
            }

            if (requestBody != null)
            {
                RequestBodyType = requestBody.GetType();

                if (RequestBodyType == typeof(byte[])) _RequestBodyBytes = requestBody as byte[];
                else if (RequestBodyType == typeof(Stream)) _RequestBodyStream = requestBody as MemoryStream;
                else if (RequestBodyType == typeof(string)) _RequestBodyString = requestBody as string;
                else throw new ArgumentException("Request body must be of type stream, string, or byte array.");
            }

            _HttpMethod = httpMethod.ToUpper();
            _FullUrl = fullUrl;
            _Uri = new Uri(_FullUrl);

            _DateKey = HmacSha256(
                Encoding.UTF8.GetBytes("AWS4" + SecretKey),
                Encoding.UTF8.GetBytes(Timestamp.Substring(0, 8)));

            _DateRegionKey = HmacSha256(
                _DateKey,
                Encoding.UTF8.GetBytes(Region));

            _DateRegionServiceKey = HmacSha256(
                _DateRegionKey,
                Encoding.UTF8.GetBytes(Service));

            _SigningKey = HmacSha256(
                _DateRegionServiceKey,
                Encoding.UTF8.GetBytes("aws4_request"));
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Human-readable version of the object.
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            string ret = "";
            ret += "V4 Signature Result" + Environment.NewLine;
            ret += "-------------------" + Environment.NewLine;
            ret += "Timestamp            : " + Timestamp + Environment.NewLine;
            ret += "Access key           : " + AccessKey + Environment.NewLine;
            ret += "Secret key           : " + SecretKey + Environment.NewLine;
            ret += "Region               : " + Region + Environment.NewLine;
            ret += "Service              : " + Service + Environment.NewLine;
            ret += "HTTP method          : " + HttpMethod + Environment.NewLine;
            ret += "Full URL             : " + FullUrl + Environment.NewLine;
            ret += "Protocol             : " + Protocol + Environment.NewLine;
            ret += "Port                 : " + Port + Environment.NewLine;
            ret += "Hostname             : " + Hostname + Environment.NewLine;
            ret += "Full URL, no query   : " + FullUrlWithoutQuery + Environment.NewLine;
            ret += "Path                 : " + Path + Environment.NewLine;
            ret += "Querystring          : " + Querystring + Environment.NewLine;
            ret += "Querystring elements : " + Environment.NewLine;

            for (int i = 0; i < QueryElements.AllKeys.Count(); i++)
            {
                string key = QueryElements.GetKey(i);
                ret += "| " + key + ": " + QueryElements.Get(key) + Environment.NewLine;
            }

            ret += "Host header          : " + HostHeader + Environment.NewLine;
            ret += "Request headers      : " + Environment.NewLine;

            for (int i = 0; i < Headers.AllKeys.Count(); i++)
            {
                string key = Headers.GetKey(i);
                ret += "| " + key + ": " + Headers.Get(key) + Environment.NewLine;
            }

            ret += "Payload hashing      : " + PayloadHash.ToString() + Environment.NewLine;
            ret += "Request body type    : " + (RequestBodyType == null ? "null" : RequestBodyType.ToString()) + Environment.NewLine;
            ret += "Canonical URI        : " + CanonicalUri + Environment.NewLine;
            ret += "Canonical query      : " + CanonicalQuerystring + Environment.NewLine;
            ret += "Canonical headers    : " 
                + Environment.NewLine 
                + "[start]" + CanonicalHeaders + "[end]" + Environment.NewLine;
            ret += "Signed headers       : " + Environment.NewLine;

            foreach (string header in SignedHeaders)
            {
                ret += "| " + header + Environment.NewLine;
            }

            ret += "Canonical request    : "
                + Environment.NewLine
                + "[start]" + CanonicalRequest + "[end]" + Environment.NewLine;
            ret += "String to sign       : "
                + Environment.NewLine
                + "[start]" + StringToSign + "[end]" + Environment.NewLine;

            ret += "Keys                 : "
                + Environment.NewLine
                +  "| Date key           : " + DateKey + Environment.NewLine
                +  "| Region key         : " + RegionKey + Environment.NewLine
                +  "| Service key        : " + ServiceKey + Environment.NewLine
                +  "| Signing key        : " + SigningKey + Environment.NewLine;

            ret += "Signature            : " + Signature + Environment.NewLine;
            ret += "Authorization header : " + AuthorizationHeader + Environment.NewLine;
            return ret;
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        /// <param name="disposing">Disposing.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_Disposed)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects)
                }

                // TODO: free unmanaged resources (unmanaged objects) and override finalizer
                // TODO: set large fields to null
                _Disposed = true;
            }
        }

        /// <summary>
        /// Dispose.
        /// </summary>
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region Private-Methods

        private byte[] Sha256(byte[] bytes)
        {
            if (bytes == null) return null;

            using (SHA256 sha256 = SHA256.Create())
            {
                return sha256.ComputeHash(bytes);
            }
        }

        private byte[] Sha256(Stream stream)
        {
            stream.Seek(0, SeekOrigin.Begin);

            using (SHA256 sha256 = SHA256.Create())
            {
                using (CryptoStream cs = new CryptoStream(stream, sha256, CryptoStreamMode.Write))
                {
                    byte[] buffer = new byte[_StreamBufferSize];
                    int read = 0;

                    while (true)
                    {
                        read = stream.Read(buffer, 0, buffer.Length);
                        if (read > 0)
                        {
                            cs.Write(buffer, 0, read);
                        }
                        else
                        {
                            break;
                        }
                    }
                    
                    cs.FlushFinalBlock();
                }

                return sha256.Hash;
            }
        }

        private byte[] HmacSha256(byte[] key, byte[] bytes)
        {
            using (HMACSHA256 hash = new HMACSHA256(key))
            {
                return hash.ComputeHash(bytes);
            }
        }

        #endregion
    }
}
