namespace Test.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Text;

    internal static class V2TestSupport
    {
        internal const string AccessKey = "AKIDEXAMPLE";
        internal const string SecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        internal const string AwsExampleAccessKey = "AKIAIOSFODNN7EXAMPLE";
        internal const string AwsExampleSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        internal const string Date = "Tue, 27 Mar 2007 19:36:42 +0000";

        internal static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!object.Equals(expected, actual))
            {
                throw new InvalidOperationException("Assertion failed (" + message + "): expected '" + expected + "', got '" + actual + "'");
            }
        }

        internal static void AssertTrue(bool condition, string message)
        {
            if (!condition)
            {
                throw new InvalidOperationException("Assertion failed: " + message);
            }
        }

        internal static void AssertNotNull(object value, string message)
        {
            if (value == null)
            {
                throw new InvalidOperationException("Assertion failed: " + message + " should not be null");
            }
        }

        internal static void AssertThrows<TException>(Action action) where TException : Exception
        {
            bool threw = false;

            try
            {
                action();
            }
            catch (TException)
            {
                threw = true;
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Expected " + typeof(TException).Name + " but got " + ex.GetType().Name + ": " + ex.Message, ex);
            }

            if (!threw)
            {
                throw new InvalidOperationException("Expected " + typeof(TException).Name + " but no exception was thrown");
            }
        }

        internal static NameValueCollection HeadersWithDate()
        {
            return new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
            {
                { "Date", Date }
            };
        }

        internal static NameValueCollection HeadersWithDateAndHost(string host)
        {
            return new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
            {
                { "Host", host },
                { "Date", Date }
            };
        }

        internal static V2AuthorizationFields ParseAuthorizationHeader(string authorizationHeader)
        {
            if (String.IsNullOrEmpty(authorizationHeader))
            {
                throw new FormatException("Authorization header is empty.");
            }

            const string prefix = "AWS ";
            if (!authorizationHeader.StartsWith(prefix, StringComparison.Ordinal))
            {
                throw new FormatException("Authorization header does not start with AWS.");
            }

            string rest = authorizationHeader.Substring(prefix.Length);
            int separatorIndex = rest.IndexOf(':');
            if (separatorIndex < 1 || separatorIndex == rest.Length - 1)
            {
                throw new FormatException("Authorization header does not contain access key and signature.");
            }

            V2AuthorizationFields fields = new V2AuthorizationFields
            {
                AccessKey = rest.Substring(0, separatorIndex),
                Signature = rest.Substring(separatorIndex + 1)
            };

            ValidateBase64Signature(fields.Signature);
            return fields;
        }

        internal static V2SignedUrlFields ParseSignedUrl(string signedUrl)
        {
            if (String.IsNullOrEmpty(signedUrl))
            {
                throw new FormatException("Signed URL is empty.");
            }

            Uri uri = new Uri(signedUrl);
            string query = uri.Query.TrimStart('?');
            string[] elements = query.Split('&');
            List<string> retainedElements = new List<string>();
            V2SignedUrlFields fields = new V2SignedUrlFields();

            foreach (string element in elements)
            {
                if (String.IsNullOrEmpty(element))
                {
                    continue;
                }

                string name;
                string value;
                SplitQueryElement(element, out name, out value);

                if (String.Equals(name, "AWSAccessKeyId", StringComparison.OrdinalIgnoreCase))
                {
                    fields.AccessKey = UrlDecode(value);
                }
                else if (String.Equals(name, "Expires", StringComparison.OrdinalIgnoreCase))
                {
                    fields.Expires = Int64.Parse(UrlDecode(value));
                }
                else if (String.Equals(name, "Signature", StringComparison.OrdinalIgnoreCase))
                {
                    fields.Signature = UrlDecode(value);
                }
                else
                {
                    retainedElements.Add(element);
                }
            }

            if (String.IsNullOrEmpty(fields.AccessKey))
            {
                throw new FormatException("Signed URL is missing AWSAccessKeyId.");
            }

            if (fields.Expires < 1)
            {
                throw new FormatException("Signed URL is missing Expires.");
            }

            if (String.IsNullOrEmpty(fields.Signature))
            {
                throw new FormatException("Signed URL is missing Signature.");
            }

            ValidateBase64Signature(fields.Signature);

            string baseUrl = uri.GetLeftPart(UriPartial.Path);
            if (retainedElements.Count > 0)
            {
                baseUrl += "?" + String.Join("&", retainedElements);
            }

            fields.UrlWithoutSignatureParameters = baseUrl;
            return fields;
        }

        internal static void ValidateBase64Signature(string signature)
        {
            byte[] bytes = Convert.FromBase64String(signature);
            AssertEqual(20, bytes.Length, "HMAC-SHA1 signature byte length");
        }

        internal static string UrlDecode(string value)
        {
            if (value == null)
            {
                return null;
            }

            return Uri.UnescapeDataString(value.Replace("+", "%20"));
        }

        private static void SplitQueryElement(string element, out string name, out string value)
        {
            int separatorIndex = element.IndexOf('=');
            if (separatorIndex >= 0)
            {
                name = UrlDecode(element.Substring(0, separatorIndex));
                value = element.Substring(separatorIndex + 1);
            }
            else
            {
                name = UrlDecode(element);
                value = "";
            }
        }
    }
}
