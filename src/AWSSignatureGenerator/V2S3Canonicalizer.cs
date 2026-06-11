namespace AWSSignatureGenerator
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Security.Cryptography;
    using System.Text;

    internal static class V2S3Canonicalizer
    {
        internal static readonly string AmazonS3ServiceHost = "s3.amazonaws.com";

        // S3 SigV2 canonical resource includes only S3 subresources and response header overrides.
        private static readonly HashSet<string> SubresourceNames = new HashSet<string>(StringComparer.Ordinal)
        {
            "acl",
            "analytics",
            "cors",
            "delete",
            "encryption",
            "inventory",
            "legal-hold",
            "lifecycle",
            "location",
            "logging",
            "metrics",
            "notification",
            "object-lock",
            "partNumber",
            "policy",
            "publicAccessBlock",
            "replication",
            "requestPayment",
            "restore",
            "retention",
            "tagging",
            "torrent",
            "uploadId",
            "uploads",
            "versionId",
            "versioning",
            "versions",
            "website",
            "response-cache-control",
            "response-content-disposition",
            "response-content-encoding",
            "response-content-language",
            "response-content-type",
            "response-expires"
        };

        internal static NameValueCollection NormalizeHeaders(NameValueCollection headers)
        {
            if (headers == null)
            {
                return new NameValueCollection(StringComparer.InvariantCultureIgnoreCase);
            }

            NameValueCollection normalized = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase);

            for (int i = 0; i < headers.Count; i++)
            {
                string key = headers.GetKey(i);
                string[] values = headers.GetValues(key);

                if (values == null || values.Length == 0)
                {
                    normalized.Add(key, headers.Get(key));
                }
                else
                {
                    foreach (string value in values)
                    {
                        normalized.Add(key, value);
                    }
                }
            }

            return normalized;
        }

        internal static string GetHeaderValue(NameValueCollection headers, string headerName)
        {
            if (headers == null || String.IsNullOrEmpty(headerName))
            {
                return "";
            }

            for (int i = 0; i < headers.Count; i++)
            {
                string key = headers.GetKey(i);

                if (String.Equals(key, headerName, StringComparison.OrdinalIgnoreCase))
                {
                    string value = headers.Get(key);
                    if (value == null)
                    {
                        return "";
                    }

                    return value.Trim();
                }
            }

            return "";
        }

        internal static bool HasAmzDateHeader(NameValueCollection headers)
        {
            if (headers == null)
            {
                return false;
            }

            for (int i = 0; i < headers.Count; i++)
            {
                string key = headers.GetKey(i);

                if (String.Equals(key, "x-amz-date", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        internal static string CanonicalizeAmzHeaders(NameValueCollection headers)
        {
            if (headers == null || headers.Count < 1)
            {
                return "";
            }

            SortedDictionary<string, List<string>> valuesByHeader =
                new SortedDictionary<string, List<string>>(StringComparer.Ordinal);

            for (int i = 0; i < headers.Count; i++)
            {
                string key = headers.GetKey(i);
                if (String.IsNullOrEmpty(key))
                {
                    continue;
                }

                string lowerKey = key.ToLowerInvariant();
                if (!lowerKey.StartsWith("x-amz-", StringComparison.Ordinal))
                {
                    continue;
                }

                if (!valuesByHeader.ContainsKey(lowerKey))
                {
                    valuesByHeader.Add(lowerKey, new List<string>());
                }

                string[] values = headers.GetValues(key);
                if (values == null || values.Length == 0)
                {
                    valuesByHeader[lowerKey].Add(NormalizeHeaderValue(headers.Get(key)));
                }
                else
                {
                    foreach (string value in values)
                    {
                        valuesByHeader[lowerKey].Add(NormalizeHeaderValue(value));
                    }
                }
            }

            StringBuilder builder = new StringBuilder();

            foreach (KeyValuePair<string, List<string>> pair in valuesByHeader)
            {
                List<string> values = pair.Value;

                builder.Append(pair.Key);
                builder.Append(":");
                builder.Append(String.Join(",", values));
                builder.Append("\n");
            }

            return builder.ToString();
        }

        internal static string CanonicalizeResource(Uri uri, string rawPath, string rawQuerystring, string bucketName)
        {
            if (uri == null) throw new ArgumentNullException(nameof(uri));

            string resourcePath = String.IsNullOrEmpty(rawPath) ? "/" : rawPath;
            string bucket = bucketName;

            if (String.IsNullOrEmpty(bucket))
            {
                bucket = InferVirtualHostedBucket(uri.Host);
            }

            string resource;

            if (!String.IsNullOrEmpty(bucket))
            {
                string bucketPrefix = "/" + bucket;

                if (String.Equals(resourcePath, bucketPrefix, StringComparison.Ordinal)
                    || resourcePath.StartsWith(bucketPrefix + "/", StringComparison.Ordinal))
                {
                    resource = resourcePath;
                }
                else
                {
                    resource = bucketPrefix + (resourcePath.StartsWith("/", StringComparison.Ordinal) ? resourcePath : "/" + resourcePath);
                }
            }
            else
            {
                resource = resourcePath;
            }

            string canonicalQuery = CanonicalizeSubresourceQuery(rawQuerystring);
            if (!String.IsNullOrEmpty(canonicalQuery))
            {
                resource += "?" + canonicalQuery;
            }

            return resource;
        }

        internal static NameValueCollection ParseQueryElements(string rawQuerystring)
        {
            NameValueCollection result = new NameValueCollection(StringComparer.Ordinal);

            if (String.IsNullOrEmpty(rawQuerystring))
            {
                return result;
            }

            string query = rawQuerystring.TrimStart('?');
            if (String.IsNullOrEmpty(query))
            {
                return result;
            }

            string[] elements = query.Split('&');
            foreach (string element in elements)
            {
                V2QueryParameter parameter = ParseQueryParameter(element);
                result.Add(UrlDecode(parameter.Name), parameter.HasValue ? UrlDecode(parameter.Value) : null);
            }

            return result;
        }

        internal static string SignHmacSha1Base64(string secretKey, string stringToSign)
        {
            using (HMACSHA1 hash = new HMACSHA1(Encoding.UTF8.GetBytes(secretKey)))
            {
                byte[] signatureBytes = hash.ComputeHash(Encoding.UTF8.GetBytes(stringToSign));
                return Convert.ToBase64String(signatureBytes);
            }
        }

        internal static string UriEncode(string value)
        {
            if (value == null)
            {
                return "";
            }

            StringBuilder builder = new StringBuilder();
            byte[] utf8Bytes = Encoding.UTF8.GetBytes(value);

            foreach (byte b in utf8Bytes)
            {
                char c = (char)b;
                if ((c >= 'A' && c <= 'Z')
                    || (c >= 'a' && c <= 'z')
                    || (c >= '0' && c <= '9')
                    || c == '_'
                    || c == '-'
                    || c == '~'
                    || c == '.')
                {
                    builder.Append(c);
                }
                else
                {
                    builder.Append('%');
                    builder.Append(b.ToString("X2"));
                }
            }

            return builder.ToString();
        }

        internal static bool HasQueryParameter(string rawQuerystring, string name)
        {
            if (String.IsNullOrEmpty(rawQuerystring))
            {
                return false;
            }

            string query = rawQuerystring.TrimStart('?');
            if (String.IsNullOrEmpty(query))
            {
                return false;
            }

            string[] elements = query.Split('&');
            foreach (string element in elements)
            {
                V2QueryParameter parameter = ParseQueryParameter(element);
                string decodedName = UrlDecode(parameter.Name);

                if (String.Equals(decodedName, name, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        internal static void ParseRawPathAndQuerystring(string fullUrl, out string rawPath, out string rawQuerystring)
        {
            rawPath = "/";
            rawQuerystring = "";

            int schemeEnd = fullUrl.IndexOf("://", StringComparison.Ordinal);
            if (schemeEnd < 0)
            {
                return;
            }

            int authorityStart = schemeEnd + 3;
            int pathStart = fullUrl.IndexOf('/', authorityStart);
            int queryStart = fullUrl.IndexOf('?', authorityStart);

            if (pathStart < 0 || (queryStart >= 0 && queryStart < pathStart))
            {
                if (queryStart >= 0)
                {
                    rawQuerystring = fullUrl.Substring(queryStart);
                }

                return;
            }

            string pathAndQuery = fullUrl.Substring(pathStart);
            int queryIndex = pathAndQuery.IndexOf("?", StringComparison.Ordinal);

            if (queryIndex >= 0)
            {
                rawPath = pathAndQuery.Substring(0, queryIndex);
                rawQuerystring = pathAndQuery.Substring(queryIndex);
            }
            else
            {
                rawPath = pathAndQuery;
            }

            if (String.IsNullOrEmpty(rawPath))
            {
                rawPath = "/";
            }
        }

        private static string CanonicalizeSubresourceQuery(string rawQuerystring)
        {
            if (String.IsNullOrEmpty(rawQuerystring))
            {
                return "";
            }

            string query = rawQuerystring.TrimStart('?');
            if (String.IsNullOrEmpty(query))
            {
                return "";
            }

            List<V2QueryParameter> included = new List<V2QueryParameter>();
            string[] elements = query.Split('&');

            foreach (string element in elements)
            {
                V2QueryParameter parameter = ParseQueryParameter(element);
                string decodedName = UrlDecode(parameter.Name);

                if (SubresourceNames.Contains(decodedName))
                {
                    included.Add(new V2QueryParameter
                    {
                        Name = decodedName,
                        Value = parameter.HasValue ? parameter.Value : null,
                        HasValue = parameter.HasValue
                    });
                }
            }

            included.Sort((left, right) =>
            {
                int nameComparison = String.Compare(left.Name, right.Name, StringComparison.Ordinal);
                if (nameComparison != 0)
                {
                    return nameComparison;
                }

                return String.Compare(left.Value ?? "", right.Value ?? "", StringComparison.Ordinal);
            });

            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < included.Count; i++)
            {
                if (i > 0)
                {
                    builder.Append("&");
                }

                builder.Append(included[i].Name);
                if (included[i].HasValue)
                {
                    builder.Append("=");
                    builder.Append(included[i].Value ?? "");
                }
            }

            return builder.ToString();
        }

        private static V2QueryParameter ParseQueryParameter(string element)
        {
            V2QueryParameter parameter = new V2QueryParameter();

            if (element == null)
            {
                parameter.Name = "";
                return parameter;
            }

            int separatorIndex = element.IndexOf("=", StringComparison.Ordinal);
            if (separatorIndex >= 0)
            {
                parameter.Name = element.Substring(0, separatorIndex);
                parameter.Value = element.Substring(separatorIndex + 1);
                parameter.HasValue = true;
            }
            else
            {
                parameter.Name = element;
                parameter.Value = null;
                parameter.HasValue = false;
            }

            return parameter;
        }

        private static string InferVirtualHostedBucket(string host)
        {
            if (String.IsNullOrEmpty(host))
            {
                return null;
            }

            string lowerHost = host.ToLowerInvariant();

            if (String.Equals(lowerHost, AmazonS3ServiceHost, StringComparison.Ordinal)
                || lowerHost.StartsWith("s3.", StringComparison.Ordinal)
                || lowerHost.StartsWith("s3-", StringComparison.Ordinal))
            {
                return null;
            }

            int s3DotIndex = lowerHost.IndexOf(".s3.", StringComparison.Ordinal);
            if (s3DotIndex > 0 && lowerHost.EndsWith(".amazonaws.com", StringComparison.Ordinal))
            {
                return host.Substring(0, s3DotIndex);
            }

            int s3DashIndex = lowerHost.IndexOf(".s3-", StringComparison.Ordinal);
            if (s3DashIndex > 0 && lowerHost.EndsWith(".amazonaws.com", StringComparison.Ordinal))
            {
                return host.Substring(0, s3DashIndex);
            }

            const string standardSuffix = ".s3.amazonaws.com";
            if (lowerHost.EndsWith(standardSuffix, StringComparison.Ordinal) && lowerHost.Length > standardSuffix.Length)
            {
                return host.Substring(0, host.Length - standardSuffix.Length);
            }

            return null;
        }

        private static string NormalizeHeaderValue(string value)
        {
            if (value == null)
            {
                return "";
            }

            string unfolded = value.Replace("\r\n", " ").Replace("\n", " ").Replace("\r", " ");
            string trimmed = unfolded.Trim();
            StringBuilder builder = new StringBuilder();
            bool previousWasWhitespace = false;

            foreach (char c in trimmed)
            {
                if (Char.IsWhiteSpace(c))
                {
                    if (!previousWasWhitespace)
                    {
                        builder.Append(' ');
                    }

                    previousWasWhitespace = true;
                }
                else
                {
                    builder.Append(c);
                    previousWasWhitespace = false;
                }
            }

            return builder.ToString();
        }

        private static string UrlDecode(string value)
        {
            if (value == null)
            {
                return null;
            }

            return Uri.UnescapeDataString(value.Replace("+", "%20"));
        }
    }
}
