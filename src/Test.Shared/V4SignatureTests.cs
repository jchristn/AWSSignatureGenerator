namespace Test.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using AWSSignatureGenerator;

    /// <summary>
    /// All V4 signature test cases. Used by both Test.Automated and Test.Xunit.
    /// </summary>
    public static class V4SignatureTests
    {
        private const string _ExampleAccessKey = "AKIDEXAMPLE";
        private const string _ExampleSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
        private const string _ExampleRegion = "us-east-1";
        private const string _ExampleService = "service";
        private const string _ExampleTimestamp = "20150830T123600Z";

        // Official AWS documentation test credentials
        private const string _AwsAccessKey = "AKIAIOSFODNN7EXAMPLE";
        private const string _AwsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

        /// <summary>
        /// Retrieve all test cases.
        /// </summary>
        /// <returns>List of test cases.</returns>
        public static List<TestCase> GetAllTests()
        {
            return new List<TestCase>
            {
                // ================================================================
                // Constructor validation tests
                // ================================================================
                new TestCase
                {
                    Name = "Constructor_NullTimestamp_Throws",
                    Description = "Null timestamp throws ArgumentNullException",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        AssertThrows<ArgumentNullException>(() =>
                            new V4SignatureResult(null, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers));
                    }
                },
                new TestCase
                {
                    Name = "Constructor_EmptyHttpMethod_Throws",
                    Description = "Empty HTTP method throws ArgumentNullException",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        AssertThrows<ArgumentNullException>(() =>
                            new V4SignatureResult(_ExampleTimestamp, "", "http://example.com/", "key", "secret", "us-east-1", "s3", headers));
                    }
                },
                new TestCase
                {
                    Name = "Constructor_InvalidTimestamp_Throws",
                    Description = "Malformed timestamp throws FormatException",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        AssertThrows<FormatException>(() =>
                            new V4SignatureResult("not-a-timestamp", "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers));
                    }
                },
                new TestCase
                {
                    Name = "Constructor_InvalidRequestBodyType_Throws",
                    Description = "Unsupported request body type throws ArgumentException",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        AssertThrows<ArgumentException>(() =>
                            new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, 12345));
                    }
                },

                // ================================================================
                // Case-insensitive host header (GitHub issue #2)
                // ================================================================
                new TestCase
                {
                    Name = "Constructor_HostHeader_Lowercase",
                    Description = "Lowercase 'host' header is accepted",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertNotNull(result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_HostHeader_Uppercase",
                    Description = "Uppercase 'Host' header is accepted (issue #2)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "Host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertNotNull(result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_HostHeader_MixedCase",
                    Description = "Mixed-case 'HOST' header is accepted",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "HOST", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertNotNull(result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_MissingHostHeader_Throws",
                    Description = "Missing host header throws ArgumentException",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "x-amz-date", _ExampleTimestamp } };
                        AssertThrows<ArgumentException>(() =>
                            new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers));
                    }
                },

                // ================================================================
                // Headers setter null safety
                // ================================================================
                new TestCase
                {
                    Name = "Constructor_NullHeaders_NoThrow",
                    Description = "Null headers collection does not throw NullReferenceException",
                    TestAction = () =>
                    {
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", null))
                        {
                            AssertNotNull(result.Headers, "Headers");
                        }
                    }
                },

                // ================================================================
                // Request body type handling (Stream fix)
                // ================================================================
                new TestCase
                {
                    Name = "Constructor_StringBody_Accepted",
                    Description = "String request body is accepted",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, "hello world"))
                        {
                            AssertEqual(typeof(string), result.RequestBodyType, "RequestBodyType");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_ByteArrayBody_Accepted",
                    Description = "Byte array request body is accepted",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        byte[] body = Encoding.UTF8.GetBytes("hello world");
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, body))
                        {
                            AssertEqual(typeof(byte[]), result.RequestBodyType, "RequestBodyType");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_MemoryStreamBody_Accepted",
                    Description = "MemoryStream request body is accepted (was broken: typeof(Stream) never matched)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes("hello world")))
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, ms))
                        {
                            AssertEqual(typeof(MemoryStream), result.RequestBodyType, "RequestBodyType");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Constructor_FileStreamBody_Accepted",
                    Description = "FileStream (a Stream subclass) is accepted",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        string tempFile = System.IO.Path.GetTempFileName();
                        try
                        {
                            File.WriteAllText(tempFile, "test data");
                            using (FileStream fs = File.OpenRead(tempFile))
                            using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, fs))
                            {
                                AssertTrue(result.RequestBodyType == typeof(FileStream), "RequestBodyType should be FileStream, got " + result.RequestBodyType);
                            }
                        }
                        finally
                        {
                            if (File.Exists(tempFile)) File.Delete(tempFile);
                        }
                    }
                },

                // ================================================================
                // Stream hashing does not corrupt the stream
                // ================================================================
                new TestCase
                {
                    Name = "HashedPayload_Stream_RepeatedAccess",
                    Description = "Accessing HashedPayload multiple times with stream body returns same hash without error",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes("test payload")))
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, ms))
                        {
                            string hash1 = result.HashedPayload;
                            string hash2 = result.HashedPayload;
                            AssertEqual(hash1, hash2, "HashedPayload should be consistent across calls");
                            AssertTrue(ms.CanRead, "Stream should still be readable after hashing");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_Stream_ResetPosition",
                    Description = "Stream position is reset to beginning after hashing",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes("test payload")))
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, ms))
                        {
                            string unused = result.HashedPayload;
                            AssertEqual(0L, ms.Position, "Stream position should be 0 after hashing");
                        }
                    }
                },

                // ================================================================
                // IDisposable behavior
                // ================================================================
                new TestCase
                {
                    Name = "Dispose_DoesNotThrow",
                    Description = "Dispose can be called without error",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers);
                        result.Dispose();
                    }
                },
                new TestCase
                {
                    Name = "Dispose_DoubleDispose_NoThrow",
                    Description = "Double dispose does not throw",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers);
                        result.Dispose();
                        result.Dispose();
                    }
                },

                // ================================================================
                // AWS V4 signature correctness — known test vector
                // From: https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
                // ================================================================
                new TestCase
                {
                    Name = "V4Signature_GetVanilla_CorrectSignature",
                    Description = "GET / with AWS example credentials produces known-correct signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.amazonaws.com" },
                            { "x-amz-date", _ExampleTimestamp }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp,
                            "GET",
                            "https://example.amazonaws.com/",
                            _ExampleAccessKey,
                            _ExampleSecretKey,
                            _ExampleRegion,
                            _ExampleService,
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            AssertTrue(result.CanonicalRequest.StartsWith("GET\n/\n\n"), "Canonical request should start with GET\\n/\\n\\n");
                            AssertTrue(result.StringToSign.StartsWith("AWS4-HMAC-SHA256\n"), "StringToSign should start with AWS4-HMAC-SHA256");
                            AssertTrue(result.AuthorizationHeader.StartsWith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), "Auth header prefix");

                            AssertNotNull(result.DateKey, "DateKey");
                            AssertNotNull(result.RegionKey, "RegionKey");
                            AssertNotNull(result.ServiceKey, "ServiceKey");
                            AssertNotNull(result.SigningKey, "SigningKey");

                            AssertEqual(64, result.Signature.Length, "Signature length");
                            AssertTrue(IsLowercaseHex(result.Signature), "Signature should be lowercase hex");

                            string expectedSignature = "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31";
                            AssertEqual(expectedSignature, result.Signature, "Signature value");
                        }
                    }
                },
                new TestCase
                {
                    Name = "V4Signature_GetWithQuerystring_CorrectSignature",
                    Description = "GET with querystring parameters produces correct canonical querystring and signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.amazonaws.com" },
                            { "x-amz-date", _ExampleTimestamp }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp,
                            "GET",
                            "https://example.amazonaws.com/?Param2=value2&Param1=value1",
                            _ExampleAccessKey,
                            _ExampleSecretKey,
                            _ExampleRegion,
                            _ExampleService,
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            AssertTrue(result.CanonicalQuerystring.StartsWith("Param1=value1&Param2=value2"),
                                "Canonical querystring should sort params: got " + result.CanonicalQuerystring);
                            AssertEqual(64, result.Signature.Length, "Signature length");
                            AssertTrue(IsLowercaseHex(result.Signature), "Signature should be lowercase hex");
                        }
                    }
                },
                new TestCase
                {
                    Name = "V4Signature_PostWithBody_CorrectSignature",
                    Description = "POST with string body hashes the body correctly",
                    TestAction = () =>
                    {
                        string body = "Param1=value1";
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.amazonaws.com" },
                            { "content-type", "application/x-www-form-urlencoded; charset=utf-8" },
                            { "x-amz-date", _ExampleTimestamp }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp,
                            "POST",
                            "https://example.amazonaws.com/",
                            _ExampleAccessKey,
                            _ExampleSecretKey,
                            _ExampleRegion,
                            _ExampleService,
                            headers,
                            body,
                            V4PayloadHashEnum.Signed))
                        {
                            string emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                            AssertTrue(result.HashedPayload != emptyHash, "HashedPayload should not be the empty hash for a non-empty body");
                            AssertEqual("POST", result.HttpMethod, "HttpMethod");
                            AssertEqual(64, result.Signature.Length, "Signature length");

                            string expectedSignature = "2f3b42f35f135abf9c562afcbbc44fc03df96dcfd4332ecebad8b39a7d4b6125";
                            AssertEqual(expectedSignature, result.Signature, "Signature value");
                        }
                    }
                },

                // ================================================================
                // Payload hashing modes
                // ================================================================
                new TestCase
                {
                    Name = "HashedPayload_EmptyBody_ReturnsEmptyHash",
                    Description = "Empty body returns the SHA-256 of empty string",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", result.HashedPayload, "Empty body hash");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_Unsigned_ReturnsLiteral",
                    Description = "Unsigned payload returns 'UNSIGNED-PAYLOAD'",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, null, V4PayloadHashEnum.Unsigned))
                        {
                            AssertEqual("UNSIGNED-PAYLOAD", result.HashedPayload, "Unsigned payload literal");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_Streaming_ReturnsLiteral",
                    Description = "Streaming payload returns 'STREAMING-UNSIGNED-PAYLOAD-TRAILER'",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, null, V4PayloadHashEnum.IsStreaming))
                        {
                            AssertEqual("STREAMING-UNSIGNED-PAYLOAD-TRAILER", result.HashedPayload, "Streaming payload literal");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_StringVsByteArray_Same",
                    Description = "Same content as string vs byte[] produces identical payload hash",
                    TestAction = () =>
                    {
                        string body = "test content";
                        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };

                        using (V4SignatureResult resultStr = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, body))
                        using (V4SignatureResult resultBytes = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, bodyBytes))
                        {
                            AssertEqual(resultStr.HashedPayload, resultBytes.HashedPayload, "String and byte[] body hash match");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_StringVsStream_Same",
                    Description = "Same content as string vs MemoryStream produces identical payload hash",
                    TestAction = () =>
                    {
                        string body = "test content";
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };

                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(body)))
                        using (V4SignatureResult resultStr = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, body))
                        using (V4SignatureResult resultStream = new V4SignatureResult(_ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers, ms))
                        {
                            AssertEqual(resultStr.HashedPayload, resultStream.HashedPayload, "String and stream body hash match");
                        }
                    }
                },

                // ================================================================
                // URL parsing
                // ================================================================
                new TestCase
                {
                    Name = "UrlParsing_PathAndQuery",
                    Description = "Path and querystring are correctly parsed from URL",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/bucket/key?acl=true", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/bucket/key", result.Path, "Path");
                            AssertEqual("?acl=true", result.Querystring, "Querystring");
                            AssertEqual("http://example.com/bucket/key", result.FullUrlWithoutQuery, "FullUrlWithoutQuery");
                        }
                    }
                },
                new TestCase
                {
                    Name = "UrlParsing_NoQuerystring",
                    Description = "URL with no querystring returns empty querystring",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/bucket/key", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/bucket/key", result.Path, "Path");
                            AssertEqual("", result.Querystring, "Querystring should be empty");
                        }
                    }
                },
                new TestCase
                {
                    Name = "UrlParsing_RootPath",
                    Description = "Root URL returns '/' as path",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/", result.Path, "Path");
                        }
                    }
                },

                // ================================================================
                // Canonical headers
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalHeaders_Lowercased",
                    Description = "Header names are lowercased in canonical headers",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "example.com" },
                            { "X-Amz-Date", _ExampleTimestamp }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(result.CanonicalHeaders.Contains("host:"), "Should contain lowercase 'host:'");
                            AssertTrue(result.CanonicalHeaders.Contains("x-amz-date:"), "Should contain lowercase 'x-amz-date:'");
                            AssertTrue(!result.CanonicalHeaders.Contains("Host:"), "Should not contain 'Host:' with capital H");
                        }
                    }
                },
                new TestCase
                {
                    Name = "CanonicalHeaders_IgnoreList",
                    Description = "Headers in the ignore list are excluded from canonical headers",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "user-agent", "test/1.0" },
                            { "expect", "100-continue" },
                            { "x-amz-date", _ExampleTimestamp }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(!result.CanonicalHeaders.Contains("user-agent:"), "user-agent should be excluded");
                            AssertTrue(!result.CanonicalHeaders.Contains("expect:"), "expect should be excluded");
                            AssertTrue(result.CanonicalHeaders.Contains("host:"), "host should be included");
                            AssertTrue(result.CanonicalHeaders.Contains("x-amz-date:"), "x-amz-date should be included");
                        }
                    }
                },
                new TestCase
                {
                    Name = "SignedHeaders_Sorted",
                    Description = "Signed headers are sorted alphabetically",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "x-amz-date", _ExampleTimestamp },
                            { "host", "example.com" },
                            { "content-type", "text/plain" }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            List<string> signedHeaders = result.SignedHeaders;
                            for (int i = 1; i < signedHeaders.Count; i++)
                            {
                                AssertTrue(string.Compare(signedHeaders[i - 1], signedHeaders[i], StringComparison.Ordinal) < 0,
                                    "SignedHeaders should be sorted: " + signedHeaders[i - 1] + " before " + signedHeaders[i]);
                            }
                        }
                    }
                },

                // ================================================================
                // Canonical querystring
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalQuerystring_Sorted",
                    Description = "Querystring parameters are sorted by key name",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?z=1&a=2&m=3", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("a=2&m=3&z=1", result.CanonicalQuerystring, "Sorted querystring");
                        }
                    }
                },
                new TestCase
                {
                    Name = "CanonicalQuerystring_EmptyValue",
                    Description = "Querystring parameter with no value",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?acl", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("acl=", result.CanonicalQuerystring, "Empty value querystring");
                        }
                    }
                },

                // ================================================================
                // Signing key derivation
                // ================================================================
                new TestCase
                {
                    Name = "SigningKeyDerivation_Deterministic",
                    Description = "Same inputs produce the same signing key",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult r1 = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", _ExampleAccessKey, _ExampleSecretKey, _ExampleRegion, _ExampleService, headers))
                        using (V4SignatureResult r2 = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", _ExampleAccessKey, _ExampleSecretKey, _ExampleRegion, _ExampleService, headers))
                        {
                            AssertEqual(r1.DateKey, r2.DateKey, "DateKey");
                            AssertEqual(r1.RegionKey, r2.RegionKey, "RegionKey");
                            AssertEqual(r1.ServiceKey, r2.ServiceKey, "ServiceKey");
                            AssertEqual(r1.SigningKey, r2.SigningKey, "SigningKey");
                            AssertEqual(r1.Signature, r2.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "SigningKeyDerivation_DifferentRegion_DifferentKey",
                    Description = "Different region produces different signing key",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult r1 = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        using (V4SignatureResult r2 = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-west-2", "s3", headers))
                        {
                            AssertTrue(r1.SigningKey != r2.SigningKey, "Different regions should produce different signing keys");
                            AssertTrue(r1.Signature != r2.Signature, "Different regions should produce different signatures");
                        }
                    }
                },

                // ================================================================
                // Authorization header format
                // ================================================================
                new TestCase
                {
                    Name = "AuthorizationHeader_Format",
                    Description = "Authorization header has correct AWS4-HMAC-SHA256 format",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.amazonaws.com" },
                            { "x-amz-date", _ExampleTimestamp }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "https://example.amazonaws.com/", _ExampleAccessKey, _ExampleSecretKey, _ExampleRegion, _ExampleService, headers))
                        {
                            string auth = result.AuthorizationHeader;
                            AssertTrue(auth.StartsWith("AWS4-HMAC-SHA256 "), "Should start with algorithm");
                            AssertTrue(auth.Contains("Credential="), "Should contain Credential=");
                            AssertTrue(auth.Contains("SignedHeaders="), "Should contain SignedHeaders=");
                            AssertTrue(auth.Contains("Signature="), "Should contain Signature=");
                            AssertTrue(auth.Contains("/aws4_request"), "Should contain /aws4_request");
                            AssertTrue(auth.Contains(_ExampleAccessKey), "Should contain access key");
                            AssertTrue(auth.Contains("20150830"), "Should contain date portion of timestamp");
                        }
                    }
                },

                // ================================================================
                // HttpMethod uppercasing
                // ================================================================
                new TestCase
                {
                    Name = "HttpMethod_Uppercased",
                    Description = "HTTP method is uppercased regardless of input",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "get", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("GET", result.HttpMethod, "HttpMethod should be uppercased");
                        }
                    }
                },

                // ================================================================
                // ToString does not throw
                // ================================================================
                new TestCase
                {
                    Name = "ToString_DoesNotThrow",
                    Description = "ToString produces output without throwing",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?foo=bar", "key", "secret", "us-east-1", "s3", headers))
                        {
                            string output = result.ToString();
                            AssertTrue(output.Length > 0, "ToString should produce non-empty output");
                            AssertTrue(output.Contains("V4 Signature Result"), "ToString should contain header");
                        }
                    }
                },

                // ================================================================
                // UriEncode correctness
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalQuerystring_SpecialCharsEncoded",
                    Description = "Special characters in querystring values are percent-encoded per AWS spec",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?key=val%20ue", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(result.CanonicalQuerystring.Contains("%20"),
                                "Space should be encoded as %20 in canonical querystring: got " + result.CanonicalQuerystring);
                        }
                    }
                },

                // ================================================================
                // Path normalization — Uri must NOT collapse double slashes (S3 keys)
                // ================================================================
                new TestCase
                {
                    Name = "Path_DoubleSlash_Preserved",
                    Description = "Double slashes in path are preserved (S3 object keys can contain //)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "s3.amazonaws.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://s3.amazonaws.com/bucket/my-object//photo.jpg", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/bucket/my-object//photo.jpg", result.Path, "Path should preserve double slashes");
                        }
                    }
                },
                new TestCase
                {
                    Name = "Path_DotSegments_Preserved",
                    Description = "Dot segments in path are preserved (not normalized away)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "s3.amazonaws.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://s3.amazonaws.com/bucket/./key/../other", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/bucket/./key/../other", result.Path, "Path should preserve dot segments");
                        }
                    }
                },

                // ================================================================
                // Canonical URI is URI-encoded with '/' preserved
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalUri_SlashesPreserved",
                    Description = "Slashes in canonical URI are not encoded",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/bucket/key", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("/bucket/key", result.CanonicalUri, "Slashes should not be encoded");
                        }
                    }
                },
                new TestCase
                {
                    Name = "CanonicalUri_SpecialCharsEncoded",
                    Description = "Special characters in path segments are percent-encoded",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/bucket/my%20photo.jpg", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(result.CanonicalUri.Contains("%20"), "Space in path should be encoded as %20: got " + result.CanonicalUri);
                            AssertTrue(result.CanonicalUri.Contains("/bucket/"), "Path structure should be preserved");
                        }
                    }
                },

                // ================================================================
                // Canonical headers — sequential spaces collapsed
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalHeaders_SequentialSpacesCollapsed",
                    Description = "Sequential spaces in header values are collapsed to a single space",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-custom", "  value  with   spaces  " }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(result.CanonicalHeaders.Contains("x-custom:value with spaces\n"),
                                "Sequential spaces should be collapsed and trimmed: got [" + result.CanonicalHeaders + "]");
                        }
                    }
                },

                // ================================================================
                // Canonical querystring — duplicate keys sorted by value
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalQuerystring_DuplicateKeys_SortedByValue",
                    Description = "Duplicate query keys are sorted by value",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?tag=zebra&tag=apple&tag=mango", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("tag=apple&tag=mango&tag=zebra", result.CanonicalQuerystring,
                                "Duplicate keys should appear sorted by value");
                        }
                    }
                },

                // ================================================================
                // Canonical querystring — case-sensitive keys
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalQuerystring_CaseSensitiveKeys",
                    Description = "Query parameter keys are case-sensitive (Foo and foo are distinct)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?Foo=1&foo=2", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual("Foo=1&foo=2", result.CanonicalQuerystring,
                                "Case-distinct keys should both appear: got " + result.CanonicalQuerystring);
                        }
                    }
                },

                // ================================================================
                // QueryElements — case-sensitive
                // ================================================================
                new TestCase
                {
                    Name = "QueryElements_CaseSensitive",
                    Description = "QueryElements treats Foo and foo as distinct keys",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?Foo=1&foo=2", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertEqual(2, result.QueryElements.Count, "Should have 2 distinct query keys");
                        }
                    }
                },

                // ================================================================
                // Canonical querystring — sort on encoded keys
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalQuerystring_SortedByEncodedKey",
                    Description = "Query params are sorted by the encoded key form",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/?a.b=1&a-c=2", "key", "secret", "us-east-1", "s3", headers))
                        {
                            // '-' (0x2D) sorts before '.' (0x2E) in both decoded and encoded ordinal
                            AssertTrue(result.CanonicalQuerystring.StartsWith("a-c=2"),
                                "a-c should sort before a.b: got " + result.CanonicalQuerystring);
                        }
                    }
                },

                // ================================================================
                // Signed headers sorted by lowered name
                // ================================================================
                new TestCase
                {
                    Name = "SignedHeaders_SortedByLoweredName",
                    Description = "Signed headers are sorted by lowered name, not original case",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "X-Amz-Date", _ExampleTimestamp },
                            { "Host", "example.com" },
                            { "Content-Type", "text/plain" }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            List<string> signedHeaders = result.SignedHeaders;
                            AssertEqual("content-type", signedHeaders[0], "First signed header");
                            AssertEqual("host", signedHeaders[1], "Second signed header");
                            AssertEqual("x-amz-date", signedHeaders[2], "Third signed header");
                        }
                    }
                },

                // ================================================================
                // Header ignore list — new entries
                // ================================================================
                new TestCase
                {
                    Name = "CanonicalHeaders_ExcludesHopByHopHeaders",
                    Description = "Hop-by-hop headers (connection, keep-alive, etc.) are excluded",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "connection", "keep-alive" },
                            { "keep-alive", "timeout=5" },
                            { "transfer-encoding", "chunked" },
                            { "proxy-authorization", "Basic abc" },
                            { "x-amz-date", _ExampleTimestamp }
                        };
                        using (V4SignatureResult result = new V4SignatureResult(_ExampleTimestamp, "GET", "http://example.com/", "key", "secret", "us-east-1", "s3", headers))
                        {
                            AssertTrue(!result.CanonicalHeaders.Contains("connection:"), "connection should be excluded");
                            AssertTrue(!result.CanonicalHeaders.Contains("keep-alive:"), "keep-alive should be excluded");
                            AssertTrue(!result.CanonicalHeaders.Contains("transfer-encoding:"), "transfer-encoding should be excluded");
                            AssertTrue(!result.CanonicalHeaders.Contains("proxy-authorization:"), "proxy-authorization should be excluded");
                            AssertTrue(result.CanonicalHeaders.Contains("host:"), "host should be included");
                            AssertTrue(result.CanonicalHeaders.Contains("x-amz-date:"), "x-amz-date should be included");
                        }
                    }
                },

                // ================================================================
                // Official AWS documentation test vectors
                // Credentials: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
                // Source: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
                // ================================================================
                new TestCase
                {
                    Name = "AWS_S3_GetObject_WithRange",
                    Description = "Official AWS test vector: S3 GET Object with Range header",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "examplebucket.s3.amazonaws.com" },
                            { "Range", "bytes=0-9" },
                            { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                            { "x-amz-date", "20130524T000000Z" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20130524T000000Z",
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/test.txt",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "s3",
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            string expectedCanonicalRequest =
                                "GET\n" +
                                "/test.txt\n" +
                                "\n" +
                                "host:examplebucket.s3.amazonaws.com\n" +
                                "range:bytes=0-9\n" +
                                "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
                                "x-amz-date:20130524T000000Z\n" +
                                "\n" +
                                "host;range;x-amz-content-sha256;x-amz-date\n" +
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                            string expectedStringToSign =
                                "AWS4-HMAC-SHA256\n" +
                                "20130524T000000Z\n" +
                                "20130524/us-east-1/s3/aws4_request\n" +
                                "7344ae5b7ee6c3e7e6b0fe0640412a37625d1fbfff95c48bbb2dc43964946972";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual(expectedStringToSign, result.StringToSign, "String to Sign");
                            AssertEqual("f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AWS_S3_PutObject_SpecialCharInPath",
                    Description = "Official AWS test vector: S3 PUT Object with $ in path and body",
                    TestAction = () =>
                    {
                        string body = "Welcome to Amazon S3.";
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "examplebucket.s3.amazonaws.com" },
                            { "Date", "Fri, 24 May 2013 00:00:00 GMT" },
                            { "x-amz-content-sha256", "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072" },
                            { "x-amz-date", "20130524T000000Z" },
                            { "x-amz-storage-class", "REDUCED_REDUNDANCY" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20130524T000000Z",
                            "PUT",
                            "https://examplebucket.s3.amazonaws.com/test$file.text",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "s3",
                            headers,
                            body,
                            V4PayloadHashEnum.Signed))
                        {
                            // $ in path must be encoded to %24
                            AssertTrue(result.CanonicalUri.Contains("%24"), "$ should be encoded to %24 in canonical URI: got " + result.CanonicalUri);

                            string expectedCanonicalRequest =
                                "PUT\n" +
                                "/test%24file.text\n" +
                                "\n" +
                                "date:Fri, 24 May 2013 00:00:00 GMT\n" +
                                "host:examplebucket.s3.amazonaws.com\n" +
                                "x-amz-content-sha256:44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072\n" +
                                "x-amz-date:20130524T000000Z\n" +
                                "x-amz-storage-class:REDUCED_REDUNDANCY\n" +
                                "\n" +
                                "date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class\n" +
                                "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072";

                            string expectedStringToSign =
                                "AWS4-HMAC-SHA256\n" +
                                "20130524T000000Z\n" +
                                "20130524/us-east-1/s3/aws4_request\n" +
                                "9e0e90d9c76de8fa5b200d8c849cd5b8dc7a3be3951ddb7f6a76b4158342019d";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual(expectedStringToSign, result.StringToSign, "String to Sign");
                            AssertEqual("98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AWS_S3_GetBucketLifecycle_EmptyQueryValue",
                    Description = "Official AWS test vector: S3 GET with query parameter with empty value",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "examplebucket.s3.amazonaws.com" },
                            { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                            { "x-amz-date", "20130524T000000Z" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20130524T000000Z",
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/?lifecycle",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "s3",
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            AssertEqual("lifecycle=", result.CanonicalQuerystring, "Empty value query param");

                            string expectedCanonicalRequest =
                                "GET\n" +
                                "/\n" +
                                "lifecycle=\n" +
                                "host:examplebucket.s3.amazonaws.com\n" +
                                "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
                                "x-amz-date:20130524T000000Z\n" +
                                "\n" +
                                "host;x-amz-content-sha256;x-amz-date\n" +
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual("fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AWS_S3_GetBucketListObjects_MultipleQueryParams",
                    Description = "Official AWS test vector: S3 GET with multiple query parameters",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "examplebucket.s3.amazonaws.com" },
                            { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                            { "x-amz-date", "20130524T000000Z" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20130524T000000Z",
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "s3",
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            AssertEqual("max-keys=2&prefix=J", result.CanonicalQuerystring, "Sorted query params");

                            string expectedCanonicalRequest =
                                "GET\n" +
                                "/\n" +
                                "max-keys=2&prefix=J\n" +
                                "host:examplebucket.s3.amazonaws.com\n" +
                                "x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" +
                                "x-amz-date:20130524T000000Z\n" +
                                "\n" +
                                "host;x-amz-content-sha256;x-amz-date\n" +
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual("34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AWS_Glacier_PutVault",
                    Description = "Official AWS test vector: Glacier PUT vault (different service, non-midnight timestamp)",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "glacier.us-east-1.amazonaws.com" },
                            { "x-amz-date", "20120525T002453Z" },
                            { "x-amz-glacier-version", "2012-06-01" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20120525T002453Z",
                            "PUT",
                            "https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "glacier",
                            headers,
                            null,
                            V4PayloadHashEnum.Signed))
                        {
                            string expectedCanonicalRequest =
                                "PUT\n" +
                                "/-/vaults/examplevault\n" +
                                "\n" +
                                "host:glacier.us-east-1.amazonaws.com\n" +
                                "x-amz-date:20120525T002453Z\n" +
                                "x-amz-glacier-version:2012-06-01\n" +
                                "\n" +
                                "host;x-amz-date;x-amz-glacier-version\n" +
                                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

                            string expectedStringToSign =
                                "AWS4-HMAC-SHA256\n" +
                                "20120525T002453Z\n" +
                                "20120525/us-east-1/glacier/aws4_request\n" +
                                "5f1da1a2d0feb614dd03d71e87928b8e449ac87614479332aced3a701f916743";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual(expectedStringToSign, result.StringToSign, "String to Sign");
                            AssertEqual("3ce5b2f2fffac9262b4da9256f8d086b4aaf42eba5f111c21681a65a127b7c2a", result.Signature, "Signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AWS_Glacier_PostArchive_WithBody",
                    Description = "Official AWS test vector: Glacier POST archive upload with body",
                    TestAction = () =>
                    {
                        string body = "Welcome to Amazon Glacier.";
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "Host", "glacier.us-east-1.amazonaws.com" },
                            { "x-amz-content-sha256", "726e392cb4d09924dbad1cc0ba3b00c3643d03d14cb4b823e2f041cff612a628" },
                            { "x-amz-date", "20120507T000000Z" },
                            { "x-amz-glacier-version", "2012-06-01" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            "20120507T000000Z",
                            "POST",
                            "https://glacier.us-east-1.amazonaws.com/-/vaults/examplevault/archives",
                            _AwsAccessKey,
                            _AwsSecretKey,
                            "us-east-1",
                            "glacier",
                            headers,
                            body,
                            V4PayloadHashEnum.Signed))
                        {
                            string expectedCanonicalRequest =
                                "POST\n" +
                                "/-/vaults/examplevault/archives\n" +
                                "\n" +
                                "host:glacier.us-east-1.amazonaws.com\n" +
                                "x-amz-content-sha256:726e392cb4d09924dbad1cc0ba3b00c3643d03d14cb4b823e2f041cff612a628\n" +
                                "x-amz-date:20120507T000000Z\n" +
                                "x-amz-glacier-version:2012-06-01\n" +
                                "\n" +
                                "host;x-amz-content-sha256;x-amz-date;x-amz-glacier-version\n" +
                                "726e392cb4d09924dbad1cc0ba3b00c3643d03d14cb4b823e2f041cff612a628";

                            AssertEqual(expectedCanonicalRequest, result.CanonicalRequest, "Canonical Request");
                            AssertEqual("b092397439375d59119072764a1e9a144677c43d9906fd98a5742c57a2855de6", result.Signature, "Signature");
                        }
                    }
                },

                // ================================================================
                // Streaming signature — new enum values
                // ================================================================
                new TestCase
                {
                    Name = "HashedPayload_StreamingSigned_ReturnsLiteral",
                    Description = "StreamingSigned returns 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD'",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers,
                            null, V4PayloadHashEnum.StreamingSigned))
                        {
                            AssertEqual("STREAMING-AWS4-HMAC-SHA256-PAYLOAD", result.HashedPayload, "StreamingSigned payload literal");
                        }
                    }
                },
                new TestCase
                {
                    Name = "HashedPayload_StreamingSignedTrailer_ReturnsLiteral",
                    Description = "StreamingSignedTrailer returns 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER'",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/", "key", "secret", "us-east-1", "s3", headers,
                            null, V4PayloadHashEnum.StreamingSignedTrailer))
                        {
                            AssertEqual("STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER", result.HashedPayload, "StreamingSignedTrailer payload literal");
                        }
                    }
                },

                // ================================================================
                // Streaming signature — seed signature validation
                // ================================================================
                new TestCase
                {
                    Name = "StreamingSigned_SeedSignature_Deterministic",
                    Description = "StreamingSigned seed signature is deterministic and differs from Signed mode",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult r1 = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        using (V4SignatureResult r2 = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        {
                            AssertEqual(r1.Signature, r2.Signature, "Seed signatures should be deterministic");
                            AssertEqual(64, r1.Signature.Length, "Signature length");
                            AssertTrue(IsLowercaseHex(r1.Signature), "Signature should be lowercase hex");
                        }
                    }
                },
                new TestCase
                {
                    Name = "StreamingSigned_DiffersFromSigned",
                    Description = "StreamingSigned seed signature differs from Signed signature for same request",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp }
                        };

                        using (V4SignatureResult rSigned = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.Signed))
                        using (V4SignatureResult rStreaming = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        {
                            AssertTrue(rSigned.Signature != rStreaming.Signature,
                                "StreamingSigned and Signed should produce different signatures");
                        }
                    }
                },

                // ================================================================
                // SigningKeyBytes
                // ================================================================
                new TestCase
                {
                    Name = "SigningKeyBytes_NotNull",
                    Description = "SigningKeyBytes property returns the raw signing key bytes",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "GET", "http://example.com/", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers))
                        {
                            AssertNotNull(result.SigningKeyBytes, "SigningKeyBytes");
                            AssertEqual(32, result.SigningKeyBytes.Length, "SigningKeyBytes length (HMAC-SHA256 = 32 bytes)");
                        }
                    }
                },
                new TestCase
                {
                    Name = "SigningKeyBytes_MatchesSigningKeyHex",
                    Description = "SigningKeyBytes matches the hex-encoded SigningKey property",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection { { "host", "example.com" } };
                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "GET", "http://example.com/", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers))
                        {
                            string hexFromBytes = BitConverter.ToString(result.SigningKeyBytes).Replace("-", "").ToLower();
                            AssertEqual(result.SigningKey, hexFromBytes, "SigningKeyBytes should match SigningKey hex");
                        }
                    }
                },

                // ================================================================
                // V4ChunkSigner — chunk signature computation
                // ================================================================
                new TestCase
                {
                    Name = "ChunkSigner_ComputeChunkSignature_Deterministic",
                    Description = "ChunkSigner produces deterministic signatures for the same input",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        {
                            byte[] chunkData = Encoding.UTF8.GetBytes("Hello");

                            using (V4ChunkSigner signer1 = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            using (V4ChunkSigner signer2 = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                string sig1 = signer1.ComputeChunkSignature(chunkData);
                                string sig2 = signer2.ComputeChunkSignature(chunkData);
                                AssertEqual(sig1, sig2, "Chunk signatures should be deterministic");
                                AssertEqual(64, sig1.Length, "Chunk signature length");
                                AssertTrue(IsLowercaseHex(sig1), "Chunk signature should be lowercase hex");
                            }
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_ChainedSignatures_Differ",
                    Description = "Successive chunk signatures differ because each chains from the previous",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        using (V4ChunkSigner signer = new V4ChunkSigner(
                            _ExampleTimestamp, _ExampleRegion, _ExampleService,
                            result.SigningKeyBytes, result.Signature))
                        {
                            string sig1 = signer.ComputeChunkSignature(Encoding.UTF8.GetBytes("chunk1"));
                            string sig2 = signer.ComputeChunkSignature(Encoding.UTF8.GetBytes("chunk2"));
                            string sigFinal = signer.ComputeChunkSignature(null);

                            AssertTrue(sig1 != sig2, "Different chunks should produce different signatures");
                            AssertTrue(sig2 != sigFinal, "Final chunk should produce a different signature");
                            AssertTrue(sig1 != sigFinal, "First and final chunk signatures should differ");
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_ValidateChunk_Success",
                    Description = "ValidateChunk returns true for a correct signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        {
                            byte[] chunkData = Encoding.UTF8.GetBytes("Hello");

                            // Compute the expected signature
                            string expectedSig;
                            using (V4ChunkSigner computeSigner = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                expectedSig = computeSigner.ComputeChunkSignature(chunkData);
                            }

                            // Validate using a fresh signer
                            using (V4ChunkSigner validateSigner = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                AssertTrue(validateSigner.ValidateChunk(chunkData, expectedSig), "ValidateChunk should return true for correct signature");
                            }
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_ValidateChunk_Failure",
                    Description = "ValidateChunk returns false for an incorrect signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        using (V4ChunkSigner signer = new V4ChunkSigner(
                            _ExampleTimestamp, _ExampleRegion, _ExampleService,
                            result.SigningKeyBytes, result.Signature))
                        {
                            AssertTrue(!signer.ValidateChunk(Encoding.UTF8.GetBytes("Hello"), "0000000000000000000000000000000000000000000000000000000000000000"),
                                "ValidateChunk should return false for wrong signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_FinalChunk_EmptyData",
                    Description = "Final chunk with null/empty data produces a valid signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSigned))
                        using (V4ChunkSigner signer1 = new V4ChunkSigner(
                            _ExampleTimestamp, _ExampleRegion, _ExampleService,
                            result.SigningKeyBytes, result.Signature))
                        using (V4ChunkSigner signer2 = new V4ChunkSigner(
                            _ExampleTimestamp, _ExampleRegion, _ExampleService,
                            result.SigningKeyBytes, result.Signature))
                        {
                            string sigNull = signer1.ComputeChunkSignature(null);
                            string sigEmpty = signer2.ComputeChunkSignature(Array.Empty<byte>());
                            AssertEqual(sigNull, sigEmpty, "Null and empty data should produce identical final chunk signatures");
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_Constructor_NullArgs_Throw",
                    Description = "V4ChunkSigner constructor throws on null arguments",
                    TestAction = () =>
                    {
                        byte[] dummyKey = new byte[32];
                        AssertThrows<ArgumentNullException>(() => new V4ChunkSigner(null, "us-east-1", "s3", dummyKey, "seed"));
                        AssertThrows<ArgumentNullException>(() => new V4ChunkSigner("20150830T123600Z", null, "s3", dummyKey, "seed"));
                        AssertThrows<ArgumentNullException>(() => new V4ChunkSigner("20150830T123600Z", "us-east-1", null, dummyKey, "seed"));
                        AssertThrows<ArgumentNullException>(() => new V4ChunkSigner("20150830T123600Z", "us-east-1", "s3", null, "seed"));
                        AssertThrows<ArgumentNullException>(() => new V4ChunkSigner("20150830T123600Z", "us-east-1", "s3", dummyKey, null));
                    }
                },

                // ================================================================
                // V4ChunkSigner — trailer signature
                // ================================================================
                new TestCase
                {
                    Name = "ChunkSigner_TrailerSignature_Deterministic",
                    Description = "Trailer signature is deterministic",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSignedTrailer))
                        {
                            SortedDictionary<string, string> trailers = new SortedDictionary<string, string>
                            {
                                { "x-amz-checksum-crc32", "aBC123==" }
                            };

                            string sig1, sig2;
                            using (V4ChunkSigner signer1 = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                signer1.ComputeChunkSignature(Encoding.UTF8.GetBytes("Hello"));
                                signer1.ComputeChunkSignature(null); // final
                                sig1 = signer1.ComputeTrailerSignature(trailers);
                            }

                            using (V4ChunkSigner signer2 = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                signer2.ComputeChunkSignature(Encoding.UTF8.GetBytes("Hello"));
                                signer2.ComputeChunkSignature(null); // final
                                sig2 = signer2.ComputeTrailerSignature(trailers);
                            }

                            AssertEqual(sig1, sig2, "Trailer signatures should be deterministic");
                            AssertEqual(64, sig1.Length, "Trailer signature length");
                            AssertTrue(IsLowercaseHex(sig1), "Trailer signature should be lowercase hex");
                        }
                    }
                },
                new TestCase
                {
                    Name = "ChunkSigner_ValidateTrailer_Success",
                    Description = "ValidateTrailer returns true for a correct trailer signature",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "example.com" },
                            { "x-amz-date", _ExampleTimestamp },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" }
                        };

                        using (V4SignatureResult result = new V4SignatureResult(
                            _ExampleTimestamp, "PUT", "http://example.com/bucket/key", _ExampleAccessKey, _ExampleSecretKey,
                            _ExampleRegion, _ExampleService, headers, null, V4PayloadHashEnum.StreamingSignedTrailer))
                        {
                            SortedDictionary<string, string> trailers = new SortedDictionary<string, string>
                            {
                                { "x-amz-checksum-crc32", "aBC123==" }
                            };

                            string expectedSig;
                            using (V4ChunkSigner computeSigner = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                computeSigner.ComputeChunkSignature(null); // final chunk
                                expectedSig = computeSigner.ComputeTrailerSignature(trailers);
                            }

                            using (V4ChunkSigner validateSigner = new V4ChunkSigner(
                                _ExampleTimestamp, _ExampleRegion, _ExampleService,
                                result.SigningKeyBytes, result.Signature))
                            {
                                validateSigner.ComputeChunkSignature(null); // final chunk
                                AssertTrue(validateSigner.ValidateTrailer(trailers, expectedSig),
                                    "ValidateTrailer should return true for correct signature");
                            }
                        }
                    }
                },

                // ================================================================
                // AwsChunkedStreamReader
                // ================================================================
                new TestCase
                {
                    Name = "AwsChunkedStreamReader_SingleChunk",
                    Description = "Reads a single data chunk and final chunk from aws-chunked stream",
                    TestAction = () =>
                    {
                        string wire =
                            "5;chunk-signature=aaaa\r\n" +
                            "Hello\r\n" +
                            "0;chunk-signature=bbbb\r\n" +
                            "\r\n";

                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(wire)))
                        using (AwsChunkedStreamReader reader = new AwsChunkedStreamReader(ms))
                        {
                            AwsChunkResult chunk1 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertNotNull(chunk1, "chunk1");
                            AssertEqual(false, chunk1.IsFinal, "chunk1 should not be final");
                            AssertEqual("Hello", Encoding.UTF8.GetString(chunk1.Data), "chunk1 data");
                            AssertEqual("aaaa", chunk1.Signature, "chunk1 signature");

                            AwsChunkResult chunk2 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertNotNull(chunk2, "chunk2");
                            AssertEqual(true, chunk2.IsFinal, "chunk2 should be final");
                            AssertEqual(0, chunk2.Data.Length, "Final chunk should have empty data");
                            AssertEqual("bbbb", chunk2.Signature, "chunk2 signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AwsChunkedStreamReader_MultipleChunks",
                    Description = "Reads multiple data chunks from aws-chunked stream",
                    TestAction = () =>
                    {
                        string wire =
                            "5;chunk-signature=sig1\r\n" +
                            "Hello\r\n" +
                            "6;chunk-signature=sig2\r\n" +
                            " World\r\n" +
                            "0;chunk-signature=sig3\r\n" +
                            "\r\n";

                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(wire)))
                        using (AwsChunkedStreamReader reader = new AwsChunkedStreamReader(ms))
                        {
                            AwsChunkResult c1 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertEqual("Hello", Encoding.UTF8.GetString(c1.Data), "chunk1 data");
                            AssertEqual("sig1", c1.Signature, "chunk1 sig");
                            AssertEqual(false, c1.IsFinal, "chunk1 not final");

                            AwsChunkResult c2 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertEqual(" World", Encoding.UTF8.GetString(c2.Data), "chunk2 data");
                            AssertEqual("sig2", c2.Signature, "chunk2 sig");
                            AssertEqual(false, c2.IsFinal, "chunk2 not final");

                            AwsChunkResult c3 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertEqual(true, c3.IsFinal, "chunk3 final");
                            AssertEqual("sig3", c3.Signature, "chunk3 sig");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AwsChunkedStreamReader_WithTrailers",
                    Description = "Reads trailing headers and trailer signature from aws-chunked stream",
                    TestAction = () =>
                    {
                        string wire =
                            "5;chunk-signature=sig1\r\n" +
                            "Hello\r\n" +
                            "0;chunk-signature=sig2\r\n" +
                            "\r\n" +
                            "x-amz-checksum-crc32:aBC123==\r\n" +
                            "\r\n" +
                            "0;chunk-signature=trailersig\r\n" +
                            "\r\n";

                        using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(wire)))
                        using (AwsChunkedStreamReader reader = new AwsChunkedStreamReader(ms))
                        {
                            AwsChunkResult c1 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertEqual("Hello", Encoding.UTF8.GetString(c1.Data), "chunk data");

                            AwsChunkResult c2 = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertEqual(true, c2.IsFinal, "final chunk");

                            AwsChunkResult trailer = reader.ReadNextChunkAsync().GetAwaiter().GetResult();
                            AssertNotNull(trailer, "trailer result");
                            AssertNotNull(trailer.TrailerHeaders, "TrailerHeaders");
                            AssertEqual("aBC123==", trailer.TrailerHeaders["x-amz-checksum-crc32"], "Trailer header value");
                            AssertEqual("trailersig", trailer.TrailerSignature, "Trailer signature");
                        }
                    }
                },
                new TestCase
                {
                    Name = "AwsChunkedStreamReader_Constructor_NullStream_Throws",
                    Description = "AwsChunkedStreamReader throws on null stream",
                    TestAction = () =>
                    {
                        AssertThrows<ArgumentNullException>(() => new AwsChunkedStreamReader(null));
                    }
                },

                // ================================================================
                // End-to-end: seed + chunk + trailer validation
                // ================================================================
                new TestCase
                {
                    Name = "EndToEnd_StreamingSignature_ChunkValidation",
                    Description = "End-to-end: compute seed signature, then validate chunk signatures produced by same key",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "s3.amazonaws.com" },
                            { "x-amz-date", "20130524T000000Z" },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD" },
                            { "x-amz-decoded-content-length", "11" },
                            { "content-encoding", "aws-chunked" }
                        };

                        using (V4SignatureResult seedResult = new V4SignatureResult(
                            "20130524T000000Z", "PUT", "https://s3.amazonaws.com/mybucket/mykey",
                            _AwsAccessKey, _AwsSecretKey, "us-east-1", "s3",
                            headers, null, V4PayloadHashEnum.StreamingSigned))
                        {
                            string seedSig = seedResult.Signature;
                            AssertEqual(64, seedSig.Length, "Seed signature length");

                            // Simulate two chunks: "Hello" and " World", then final
                            byte[] chunk1 = Encoding.UTF8.GetBytes("Hello");
                            byte[] chunk2 = Encoding.UTF8.GetBytes(" World");

                            // Compute expected signatures
                            string expectedSig1, expectedSig2, expectedFinal;
                            using (V4ChunkSigner computeSigner = new V4ChunkSigner(
                                "20130524T000000Z", "us-east-1", "s3",
                                seedResult.SigningKeyBytes, seedSig))
                            {
                                expectedSig1 = computeSigner.ComputeChunkSignature(chunk1);
                                expectedSig2 = computeSigner.ComputeChunkSignature(chunk2);
                                expectedFinal = computeSigner.ComputeChunkSignature(null);
                            }

                            // Validate using a fresh signer
                            using (V4ChunkSigner validateSigner = new V4ChunkSigner(
                                "20130524T000000Z", "us-east-1", "s3",
                                seedResult.SigningKeyBytes, seedSig))
                            {
                                AssertTrue(validateSigner.ValidateChunk(chunk1, expectedSig1), "Chunk 1 validation");
                                AssertTrue(validateSigner.ValidateChunk(chunk2, expectedSig2), "Chunk 2 validation");
                                AssertTrue(validateSigner.ValidateChunk(null, expectedFinal), "Final chunk validation");
                            }
                        }
                    }
                },
                new TestCase
                {
                    Name = "EndToEnd_StreamingSignatureTrailer_FullFlow",
                    Description = "End-to-end: seed + chunks + trailer validation with StreamingSignedTrailer mode",
                    TestAction = () =>
                    {
                        NameValueCollection headers = new NameValueCollection
                        {
                            { "host", "s3.amazonaws.com" },
                            { "x-amz-date", "20130524T000000Z" },
                            { "x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" },
                            { "x-amz-decoded-content-length", "5" },
                            { "x-amz-trailer", "x-amz-checksum-crc32" },
                            { "content-encoding", "aws-chunked" }
                        };

                        using (V4SignatureResult seedResult = new V4SignatureResult(
                            "20130524T000000Z", "PUT", "https://s3.amazonaws.com/mybucket/mykey",
                            _AwsAccessKey, _AwsSecretKey, "us-east-1", "s3",
                            headers, null, V4PayloadHashEnum.StreamingSignedTrailer))
                        {
                            SortedDictionary<string, string> trailers = new SortedDictionary<string, string>
                            {
                                { "x-amz-checksum-crc32", "aBC123==" }
                            };

                            // Compute all expected signatures
                            string chunkSig, finalSig, trailerSig;
                            using (V4ChunkSigner computeSigner = new V4ChunkSigner(
                                "20130524T000000Z", "us-east-1", "s3",
                                seedResult.SigningKeyBytes, seedResult.Signature))
                            {
                                chunkSig = computeSigner.ComputeChunkSignature(Encoding.UTF8.GetBytes("Hello"));
                                finalSig = computeSigner.ComputeChunkSignature(null);
                                trailerSig = computeSigner.ComputeTrailerSignature(trailers);
                            }

                            // Validate
                            using (V4ChunkSigner validateSigner = new V4ChunkSigner(
                                "20130524T000000Z", "us-east-1", "s3",
                                seedResult.SigningKeyBytes, seedResult.Signature))
                            {
                                AssertTrue(validateSigner.ValidateChunk(Encoding.UTF8.GetBytes("Hello"), chunkSig), "Chunk validation");
                                AssertTrue(validateSigner.ValidateChunk(null, finalSig), "Final chunk validation");
                                AssertTrue(validateSigner.ValidateTrailer(trailers, trailerSig), "Trailer validation");
                            }
                        }
                    }
                },
            };
        }

        #region Assertion-Helpers

        private static bool IsLowercaseHex(string s)
        {
            foreach (char c in s)
            {
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            }
            return true;
        }

        /// <summary>
        /// Assert that expected and actual values are equal.
        /// </summary>
        /// <typeparam name="T">Value type.</typeparam>
        /// <param name="expected">Expected value.</param>
        /// <param name="actual">Actual value.</param>
        /// <param name="message">Assertion description.</param>
        public static void AssertEqual<T>(T expected, T actual, string message)
        {
            if (!object.Equals(expected, actual))
                throw new Exception($"Assertion failed ({message}): expected '{expected}', got '{actual}'");
        }

        /// <summary>
        /// Assert that a condition is true.
        /// </summary>
        /// <param name="condition">Condition to evaluate.</param>
        /// <param name="message">Assertion description.</param>
        public static void AssertTrue(bool condition, string message)
        {
            if (!condition)
                throw new Exception($"Assertion failed: {message}");
        }

        /// <summary>
        /// Assert that a value is not null.
        /// </summary>
        /// <param name="value">Value to check.</param>
        /// <param name="name">Name of the value.</param>
        public static void AssertNotNull(object value, string name)
        {
            if (value == null)
                throw new Exception($"Assertion failed: {name} should not be null");
        }

        /// <summary>
        /// Assert that an action throws a specific exception type.
        /// </summary>
        /// <typeparam name="TException">Expected exception type.</typeparam>
        /// <param name="action">Action to execute.</param>
        public static void AssertThrows<TException>(Action action) where TException : Exception
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
                throw new Exception($"Expected {typeof(TException).Name} but got {ex.GetType().Name}: {ex.Message}");
            }

            if (!threw)
                throw new Exception($"Expected {typeof(TException).Name} but no exception was thrown");
        }

        #endregion
    }
}
