namespace Test.Shared
{
    using System;
    using System.Collections.Generic;
    using System.Collections.Specialized;
    using System.Threading.Tasks;

    using AWSSignatureGenerator;
    using Touchstone.Core;

    /// <summary>
    /// Shared Touchstone suites for AWS Signature Version 2 support.
    /// </summary>
    public static class V2SignatureSuites
    {
        /// <summary>
        /// All V2 signature suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                return new List<TestSuiteDescriptor>
                {
                    ConstructorSuite(),
                    OfficialAwsVectorSuite(),
                    HeaderSigningSuite(),
                    HeaderCanonicalizationSuite(),
                    CanonicalResourceSuite(),
                    SignedUrlSuite(),
                    ValidationSuite(),
                    ApiSurfaceSuite()
                };
            }
        }

        /// <summary>
        /// Constructor validation suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor ConstructorSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2Constructor",
                displayName: "AWS Signature Version 2 Constructor Validation",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2Constructor", "NullHttpMethodThrows", "Null HTTP method throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult(null, "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "EmptyHttpMethodThrows", "Empty HTTP method throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "NullUrlThrows", "Null URL throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", null, V2TestSupport.AccessKey, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "EmptyUrlThrows", "Empty URL throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", "", V2TestSupport.AccessKey, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "RelativeUrlThrows", "Relative URL throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentException>(() =>
                            new V2SignatureResult("GET", "/photos/puppy.jpg", V2TestSupport.AccessKey, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "NullAccessKeyThrows", "Null access key throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", null, V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "EmptyAccessKeyThrows", "Empty access key throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", "", V2TestSupport.SecretKey, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "NullSecretKeyThrows", "Null secret key throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, null, V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "EmptySecretKeyThrows", "Empty secret key throws", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentNullException>(() =>
                            new V2SignatureResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, "", V2TestSupport.HeadersWithDate()));
                    }),
                    Case("V2Constructor", "MissingDateThrows", "Header signing without Date or x-amz-date throws", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase);
                        V2TestSupport.AssertThrows<ArgumentException>(() =>
                            new V2SignatureResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, V2TestSupport.SecretKey, headers));
                    }),
                    Case("V2Constructor", "SignedUrlExpiresOutOfRangeThrows", "Signed URL expiration must be positive", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentOutOfRangeException>(() =>
                            new V2SignedUrlResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg", V2TestSupport.AccessKey, V2TestSupport.SecretKey, 0));
                    }),
                    Case("V2Constructor", "SignedUrlExistingAuthParameterThrows", "Signed URL rejects existing SigV2 auth query parameters", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentException>(() =>
                            new V2SignedUrlResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?Signature=abc", V2TestSupport.AccessKey, V2TestSupport.SecretKey, 1175139620));
                    }),
                    Case("V2Constructor", "SignedUrlExistingAccessKeyParameterThrows", "Signed URL rejects existing AWSAccessKeyId query parameters", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentException>(() =>
                            new V2SignedUrlResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIDEXAMPLE", V2TestSupport.AccessKey, V2TestSupport.SecretKey, 1175139620));
                    }),
                    Case("V2Constructor", "SignedUrlExistingExpiresParameterThrows", "Signed URL rejects existing Expires query parameters", () =>
                    {
                        V2TestSupport.AssertThrows<ArgumentException>(() =>
                            new V2SignedUrlResult("GET", "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?Expires=1175139620", V2TestSupport.AccessKey, V2TestSupport.SecretKey, 1175139620));
                    })
                });
        }

        /// <summary>
        /// Official AWS S3 SigV2 documentation vector suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor OfficialAwsVectorSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2OfficialAwsVectors",
                displayName: "AWS Signature Version 2 Official AWS Vectors",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2OfficialAwsVectors", "OfficialGetObject", "Official AWS GET object header-auth vector matches published SigV2 signature", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AwsExampleAccessKey,
                            V2TestSupport.AwsExampleSecretKey,
                            V2TestSupport.HeadersWithDate(),
                            "johnsmith"))
                        {
                            V2TestSupport.AssertEqual("/johnsmith/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("bWq2s1WEIj+Ydj0vQ697zp+IXMU=", result.Signature, "signature");
                            V2TestSupport.AssertEqual("AWS AKIAIOSFODNN7EXAMPLE:bWq2s1WEIj+Ydj0vQ697zp+IXMU=", result.AuthorizationHeader, "authorization header");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2OfficialAwsVectors", "OfficialPutObjectWithContentType", "Official AWS PUT object header-auth vector signs Content-Type", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", "Tue, 27 Mar 2007 21:15:45 +0000" },
                            { "Content-Type", "image/jpeg" }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "PUT",
                            "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AwsExampleAccessKey,
                            V2TestSupport.AwsExampleSecretKey,
                            headers,
                            "johnsmith"))
                        {
                            V2TestSupport.AssertEqual("PUT\n\nimage/jpeg\nTue, 27 Mar 2007 21:15:45 +0000\n/johnsmith/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("MyyxeRY7whkBe+bq8fHCL/2kKUg=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2OfficialAwsVectors", "OfficialListBucketIgnoresOrdinaryQuery", "Official AWS list-bucket vector excludes ordinary query parameters", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", "Tue, 27 Mar 2007 19:42:41 +0000" }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://johnsmith.s3.amazonaws.com/?prefix=photos&max-keys=50&marker=puppy",
                            V2TestSupport.AwsExampleAccessKey,
                            V2TestSupport.AwsExampleSecretKey,
                            headers,
                            "johnsmith"))
                        {
                            V2TestSupport.AssertEqual("/johnsmith/", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("GET\n\n\nTue, 27 Mar 2007 19:42:41 +0000\n/johnsmith/", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("htDYFYduRNen8P9ZfE/s9SuKy0U=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2OfficialAwsVectors", "OfficialCnamePutWithMetadata", "Official AWS CNAME PUT vector preserves duplicate metadata header order", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", "Tue, 27 Mar 2007 21:06:08 +0000" },
                            { "x-amz-acl", "public-read" },
                            { "content-type", "application/x-download" },
                            { "Content-MD5", "4gJE4saaMU4BqNR0kLY+lw==" },
                            { "X-Amz-Meta-ReviewedBy", "joe@johnsmith.net" },
                            { "X-Amz-Meta-ReviewedBy", "jane@johnsmith.net" },
                            { "X-Amz-Meta-FileChecksum", "0x02661779" },
                            { "X-Amz-Meta-ChecksumAlgorithm", "crc32" },
                            { "Content-Disposition", "attachment; filename=database.dat" },
                            { "Content-Encoding", "gzip" },
                            { "Content-Length", "5913339" }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "PUT",
                            "http://static.johnsmith.net:8080/db-backup.dat.gz",
                            V2TestSupport.AwsExampleAccessKey,
                            V2TestSupport.AwsExampleSecretKey,
                            headers,
                            "static.johnsmith.net"))
                        {
                            string expectedAmzHeaders = "x-amz-acl:public-read\n"
                                + "x-amz-meta-checksumalgorithm:crc32\n"
                                + "x-amz-meta-filechecksum:0x02661779\n"
                                + "x-amz-meta-reviewedby:joe@johnsmith.net,jane@johnsmith.net\n";

                            string expectedStringToSign = "PUT\n"
                                + "4gJE4saaMU4BqNR0kLY+lw==\n"
                                + "application/x-download\n"
                                + "Tue, 27 Mar 2007 21:06:08 +0000\n"
                                + expectedAmzHeaders
                                + "/static.johnsmith.net/db-backup.dat.gz";

                            V2TestSupport.AssertEqual(expectedAmzHeaders, result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual(expectedStringToSign, result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("ilyl83RwaSoYIEdixDQcA4OnAnc=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    })
                });
        }

        /// <summary>
        /// Header signing suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor HeaderSigningSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2HeaderSigning",
                displayName: "AWS Signature Version 2 Header Signing",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2HeaderSigning", "GetObjectDateOnly", "GET object with Date only produces parseable Base64 HMAC signature", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);

                            V2AuthorizationFields fields = V2TestSupport.ParseAuthorizationHeader(result.AuthorizationHeader);
                            V2TestSupport.AssertEqual(V2TestSupport.AccessKey, fields.AccessKey, "parsed access key");
                            V2TestSupport.AssertEqual(result.Signature, fields.Signature, "parsed signature");
                        }
                    }),
                    Case("V2HeaderSigning", "PutObjectContentHeaders", "PUT object signs Content-MD5 and Content-Type", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", "Tue, 27 Mar 2007 21:15:45 +0000" },
                            { "Content-MD5", "1B2M2Y8AsgTpgAmY7PhCfg==" },
                            { "Content-Type", "text/plain" }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "PUT",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("PUT\n1B2M2Y8AsgTpgAmY7PhCfg==\ntext/plain\nTue, 27 Mar 2007 21:15:45 +0000\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("olzwZnvwKN9XRILoNASFj5dlTi8=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderSigning", "DeleteObject", "DELETE object produces a parseable Base64 HMAC signature", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "DELETE",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("DELETE\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("r093wF+VH5Cgtk6OE3I+q8XArdQ=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderSigning", "HeadObject", "HEAD object produces a parseable Base64 HMAC signature", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "HEAD",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("HEAD\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("x9Bg+3m8MOoQKPG29FhUTl+T2FQ=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderSigning", "AmzDateReplacesDateElement", "x-amz-date causes empty Date element and is canonicalized", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", V2TestSupport.Date },
                            { "x-amz-date", V2TestSupport.Date }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("", result.DateElement, "date element");
                            V2TestSupport.AssertEqual("x-amz-date:Tue, 27 Mar 2007 19:36:42 +0000\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("4gK0vVW8T1eCIipxlel65ERQ/QI=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderSigning", "DuplicateAmzHeaders", "Duplicate x-amz header values are combined in request order into a parseable signature", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();
                        headers.Add("x-amz-meta-color", "red");
                        headers.Add("X-Amz-Meta-Color", "blue");

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("x-amz-meta-color:red,blue\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("I9aO8H7RgbTx39hsNhyJduD5LV8=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderSigning", "SecurityTokenHeader", "x-amz-security-token participates in header signature", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();
                        headers.Add("x-amz-meta-color", "blue");
                        headers.Add("x-amz-security-token", "token123");

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?acl&ignored=true",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?acl", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("04NzHiA/H/h1EaSHYvCgW9BN6p8=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    })
                });
        }

        /// <summary>
        /// Header canonicalization edge-case suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor HeaderCanonicalizationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2HeaderCanonicalization",
                displayName: "AWS Signature Version 2 Header Canonicalization",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2HeaderCanonicalization", "NoAmzHeadersReturnEmpty", "No x-amz headers produces an empty CanonicalizedAmzHeaders value", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                        }
                    }),
                    Case("V2HeaderCanonicalization", "AmzHeaderNamesLowercaseAndSort", "x-amz header names are lowercased and sorted ordinally", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();
                        headers.Add("X-Amz-Meta-Zeta", "last");
                        headers.Add("x-amz-meta-alpha", "first");

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            string expectedAmzHeaders = "x-amz-meta-alpha:first\n"
                                + "x-amz-meta-zeta:last\n";

                            V2TestSupport.AssertEqual(expectedAmzHeaders, result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("gbIqG9Vm1h2+kK1FoMdex39D7J0=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderCanonicalization", "AmzHeaderWhitespaceIsNormalized", "x-amz header values trim and normalize folded whitespace", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();
                        headers.Add("x-amz-meta-description", "  alpha\t  beta\r\n  gamma  ");

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("x-amz-meta-description:alpha beta gamma\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("T239RQxdmFZ+ZcLLObsIgv0Rc4M=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderCanonicalization", "EmptyAmzHeaderValueIsSigned", "Empty x-amz header values remain present in CanonicalizedAmzHeaders", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();
                        headers.Add("x-amz-meta-empty", "");

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("x-amz-meta-empty:\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("LJXAbDQbj2BWWQqy05SuROjELAw=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderCanonicalization", "MultipleAmzDateCasingVariantsCombine", "Multiple x-amz-date casing variants combine and blank the Date element", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", V2TestSupport.Date },
                            { "x-amz-date", V2TestSupport.Date },
                            { "X-Amz-Date", "Wed, 28 Mar 2007 19:36:42 +0000" }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual("", result.DateElement, "date element");
                            V2TestSupport.AssertEqual("x-amz-date:Tue, 27 Mar 2007 19:36:42 +0000,Wed, 28 Mar 2007 19:36:42 +0000\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("CI/1AINnttehZauqOODHa3+DwEY=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2HeaderCanonicalization", "LowercaseDateHeaderSignsDateElement", "Lowercase Date header names are treated case-insensitively", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "date", V2TestSupport.Date }
                        };

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2TestSupport.AssertEqual(V2TestSupport.Date, result.DateElement, "date element");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    })
                });
        }

        /// <summary>
        /// Canonicalized resource suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor CanonicalResourceSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2CanonicalResource",
                displayName: "AWS Signature Version 2 Canonicalized Resource",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2CanonicalResource", "PathStyleMatchesVirtualHostedStyle", "Path-style and virtual-hosted-style object URLs produce the same resource", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://s3.amazonaws.com/examplebucket/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "ExplicitBucketCustomEndpoint", "Explicit bucket supports custom S3-compatible endpoints", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://storage.example.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate(),
                            "examplebucket"))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "CustomEndpointWithoutBucket", "Custom endpoint without explicit bucket signs path only", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://storage.example.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("eYGVLwbQe8+xIYUM4rD/L+kYWV8=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "BucketRootVirtualHostedStyle", "Virtual-hosted-style bucket root signs bucket slash", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("hAuj/V5mLoWE57ePA8oQYRhmlTQ=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "SubresourcesAreSorted", "S3 subresources are included and sorted in canonical resource", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?uploadId=abc&ignored=true&partNumber=1",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?partNumber=1&uploadId=abc", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("lEozNh52Wo9CsOQ596v33K7nfLI=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "AllKnownSubresourcesIncluded", "Every configured S3 subresource and response override is included in canonical resource", () =>
                    {
                        List<string> parameters = new List<string>
                        {
                            "website=value",
                            "versions=value",
                            "versioning=value",
                            "versionId=value",
                            "uploads=value",
                            "uploadId=value",
                            "torrent=value",
                            "tagging=value",
                            "retention=value",
                            "restore=value",
                            "requestPayment=value",
                            "replication=value",
                            "publicAccessBlock=value",
                            "policy=value",
                            "partNumber=value",
                            "object-lock=value",
                            "notification=value",
                            "metrics=value",
                            "logging=value",
                            "location=value",
                            "lifecycle=value",
                            "legal-hold=value",
                            "inventory=value",
                            "encryption=value",
                            "delete=value",
                            "cors=value",
                            "analytics=value",
                            "acl",
                            "response-expires=value",
                            "response-content-type=value",
                            "response-content-language=value",
                            "response-content-encoding=value",
                            "response-content-disposition=value",
                            "response-cache-control=value",
                            "ignored=value"
                        };

                        List<string> expectedParameters = new List<string>();
                        foreach (string parameter in parameters)
                        {
                            if (!parameter.StartsWith("ignored=", StringComparison.Ordinal))
                            {
                                expectedParameters.Add(parameter);
                            }
                        }

                        expectedParameters.Sort(StringComparer.Ordinal);

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?" + String.Join("&", parameters),
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?" + String.Join("&", expectedParameters), result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "PathStyleBucketRootWithoutTrailingSlash", "Path-style bucket root without trailing slash signs the bucket resource", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://s3.amazonaws.com/examplebucket",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("sZkuaB2Yz4GO9/6dJLXXgJJR3aQ=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "PathStyleServiceRoot", "Path-style service root signs slash only", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://s3.amazonaws.com/",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("SrUwfAHhBJigZUEo5zYkDDalMRw=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "NoSlashBeforeSubresourceQuery", "URL without an explicit slash still preserves subresource query", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com?acl",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/?acl", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("ZP1tb85ArRFdeWtVEMVTkqEBTHU=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "RegionalVirtualHostedStyle", "Regional virtual-hosted-style S3 URLs infer the bucket", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.us-west-2.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "RegionalPathStyle", "Regional path-style S3 URLs sign the path bucket", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://s3.us-west-2.amazonaws.com/examplebucket/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "AccelerateVirtualHostedStyle", "S3 accelerate virtual-hosted-style URLs infer the bucket", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3-accelerate.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "DualstackVirtualHostedStyle", "S3 dualstack virtual-hosted-style URLs infer the bucket", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.dualstack.us-east-1.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bmEU1kxdEEID5MIVah0mIK+r0pc=", result.Signature, "signature");
                        }
                    }),
                    Case("V2CanonicalResource", "EncodedKeyPreservesRawEscapes", "Encoded object key bytes are preserved in CanonicalizedResource", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/my%20puppy%2Btoy%E2%9C%93.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/my%20puppy%2Btoy%E2%9C%93.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("4F5H/49fGBfANKEq9VnhtNHjh40=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "PlusSignKeyPreservesPlus", "Plus signs in object keys are preserved as literal plus characters", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/a+b.txt",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/a+b.txt", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("c7oGb1B+qDBqrNXbBeNrw3ZClIo=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "DuplicateSlashesAndDotSegmentsPreserved", "Duplicate slashes and dot segments are not normalized away", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos//./puppy/../toy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos//./puppy/../toy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("NbF6zDGia5wIlhjJ02NKylBy5lE=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "EmptyAndDuplicateSubresourceValues", "Empty and duplicate subresource values are included and sorted", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?uploadId=b&acl=&uploadId=a&ignored=1",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?acl=&uploadId=a&uploadId=b", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("bLG42bMnzh9oLp62oeZkg/0e2RA=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    }),
                    Case("V2CanonicalResource", "AuthQueryParametersExcluded", "SigV2 auth query parameters are excluded from header-auth canonical resources", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIDEXAMPLE&Expires=1175139620&Signature=abc&acl",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?acl", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("mwsVMfGbwCU9G11zaT5bGvJRze8=", result.Signature, "signature");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                        }
                    })
                });
        }

        /// <summary>
        /// Signed URL suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor SignedUrlSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2SignedUrl",
                displayName: "AWS Signature Version 2 Signed URLs",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2SignedUrl", "GetObjectSignedUrl", "GET signed URL includes parseable SigV2 query parameters", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertEqual("GET\n\n\n1175139620\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("Qmtft689aCVV2EsHK99DKRDuEsI=", result.Signature, "signature");
                            V2TestSupport.AssertEqual("Qmtft689aCVV2EsHK99DKRDuEsI%3D", result.EncodedSignature, "encoded signature");

                            V2SignedUrlFields fields = V2TestSupport.ParseSignedUrl(result.SignedUrl);
                            V2TestSupport.AssertEqual(V2TestSupport.AccessKey, fields.AccessKey, "access key");
                            V2TestSupport.AssertEqual(1175139620L, fields.Expires, "expiration");
                            V2TestSupport.AssertEqual(result.Signature, fields.Signature, "signature");
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlWithSubresources", "Signed URL canonicalizes subresources and response overrides", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?versionId=abc123&ignored=true&response-content-type=text/plain",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?response-content-type=text/plain&versionId=abc123", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("Tp5iJbA2p6KtYp4PC2lGS+iwohE=", result.Signature, "signature");
                            V2TestSupport.AssertEqual("Tp5iJbA2p6KtYp4PC2lGS%2BiwohE%3D", result.EncodedSignature, "encoded signature");
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlWithContentType", "PUT signed URL includes Content-Type in the string to sign", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Content-Type", "text/plain" }
                        };

                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "PUT",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620,
                            headers))
                        {
                            V2TestSupport.AssertEqual("PUT\n\ntext/plain\n1175139620\n/examplebucket/photos/puppy.jpg", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("EuF7BuT58mmwPH+dyopQeT0Zs0Q=", result.Signature, "signature");
                            V2TestSupport.AssertEqual("EuF7BuT58mmwPH%2BdyopQeT0Zs0Q%3D", result.EncodedSignature, "encoded signature");
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlWithAmzHeaders", "Signed URL includes required x-amz headers in the signature", () =>
                    {
                        NameValueCollection headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "x-amz-meta-color", "blue" }
                        };

                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620,
                            headers))
                        {
                            V2TestSupport.AssertEqual("x-amz-meta-color:blue\n", result.CanonicalizedAmzHeaders, "canonical x-amz headers");
                            V2TestSupport.AssertEqual("h7Z0y8CzGe2I2PJMr7mxlFSGhXQ=", result.Signature, "signature");
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    }),
                    Case("V2SignedUrl", "DateTimeOffsetConstructor", "DateTimeOffset constructor matches epoch-second constructor", () =>
                    {
                        DateTimeOffset expiresAt = DateTimeOffset.FromUnixTimeSeconds(1175139620);

                        using (V2SignedUrlResult byEpoch = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        using (V2SignedUrlResult byDate = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            expiresAt))
                        {
                            V2TestSupport.AssertEqual(byEpoch.Signature, byDate.Signature, "signature");
                            V2TestSupport.AssertEqual(byEpoch.SignedUrl, byDate.SignedUrl, "signed URL");
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlNoSlashBeforeSubresourceQuery", "Signed URL preserves subresource query when URL has no explicit slash", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com?acl",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/?acl", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("GET\n\n\n1175139620\n/examplebucket/?acl", result.StringToSign, "string to sign");
                            V2TestSupport.AssertEqual("fvV2eQ3s2THFtlsH0QuSubWbiwQ=", result.Signature, "signature");
                            V2TestSupport.AssertTrue(result.SignedUrl.Contains("?acl&AWSAccessKeyId=", StringComparison.Ordinal), "signed URL preserves existing query before auth parameters");
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlPreservesEncodedResponseOverride", "Signed URL signs encoded response override values exactly once", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?response-content-disposition=attachment%3B%20filename%3Dpuppy.jpg&ignored=a%2Bb",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?response-content-disposition=attachment%3B%20filename%3Dpuppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("xsbuHeUX6VxagHQXhavsU5NkGL4=", result.Signature, "signature");
                            V2TestSupport.AssertTrue(result.SignedUrl.Contains("ignored=a%2Bb", StringComparison.Ordinal), "signed URL preserves non-subresource query value");
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlPreservesSecurityTokenQuery", "Signed URL preserves existing x-amz-security-token query parameter", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?x-amz-security-token=token%2Bvalue",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertEqual("token+value", result.QueryElements["x-amz-security-token"], "decoded security token");
                            V2TestSupport.AssertTrue(result.SignedUrl.Contains("x-amz-security-token=token%2Bvalue", StringComparison.Ordinal), "signed URL preserves security token");
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    }),
                    Case("V2SignedUrl", "SignedUrlLongLivedExpiration", "Long-lived expiration values round-trip through ExpiresAt", () =>
                    {
                        DateTimeOffset expiresAt = DateTimeOffset.FromUnixTimeSeconds(4102444800L);

                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            expiresAt))
                        {
                            V2TestSupport.AssertEqual(4102444800L, result.Expires, "expiration");
                            V2TestSupport.AssertEqual(expiresAt, result.ExpiresAt, "expires at");
                            V2TestSupport.ValidateBase64Signature(result.Signature);
                            V2TestSupport.ParseSignedUrl(result.SignedUrl);
                        }
                    })
                });
        }

        /// <summary>
        /// Server-side validation and parser behavior suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor ValidationSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2Validation",
                displayName: "AWS Signature Version 2 Validation",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2Validation", "RawAuthorizationHeaderValidation", "Raw Authorization header can be parsed and recomputed", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            V2AuthorizationFields fields = V2TestSupport.ParseAuthorizationHeader(result.AuthorizationHeader);
                            using (V2SignatureResult recomputed = new V2SignatureResult(
                                "GET",
                                "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                                fields.AccessKey,
                                V2TestSupport.SecretKey,
                                headers))
                            {
                                V2TestSupport.AssertEqual(fields.Signature, recomputed.Signature, "recomputed signature");
                            }
                        }
                    }),
                    Case("V2Validation", "RawSignedUrlValidation", "Raw signed URL can be parsed and recomputed", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2SignedUrlFields fields = V2TestSupport.ParseSignedUrl(result.SignedUrl);
                            using (V2SignedUrlResult recomputed = new V2SignedUrlResult(
                                "GET",
                                fields.UrlWithoutSignatureParameters,
                                fields.AccessKey,
                                V2TestSupport.SecretKey,
                                fields.Expires))
                            {
                                V2TestSupport.AssertEqual(fields.Signature, recomputed.Signature, "recomputed signature");
                            }
                        }
                    }),
                    Case("V2Validation", "RawSignedUrlValidationRetainsQuery", "Raw signed URL validation retains non-auth query parameters", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?response-content-type=text/plain&ignored=true",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2SignedUrlFields fields = V2TestSupport.ParseSignedUrl(result.SignedUrl);
                            V2TestSupport.AssertEqual("https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?response-content-type=text/plain&ignored=true", fields.UrlWithoutSignatureParameters, "retained URL");

                            using (V2SignedUrlResult recomputed = new V2SignedUrlResult(
                                "GET",
                                fields.UrlWithoutSignatureParameters,
                                fields.AccessKey,
                                V2TestSupport.SecretKey,
                                fields.Expires))
                            {
                                V2TestSupport.AssertEqual(fields.Signature, recomputed.Signature, "recomputed signature");
                            }
                        }
                    }),
                    Case("V2Validation", "WrongAccessKeyFailsBeforeSignatureComparison", "Wrong access key fails validation before signature comparison", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2AuthorizationFields fields = V2TestSupport.ParseAuthorizationHeader(result.AuthorizationHeader.Replace(V2TestSupport.AccessKey, "OTHERKEY"));
                            V2TestSupport.AssertTrue(!String.Equals(V2TestSupport.AccessKey, fields.AccessKey, StringComparison.Ordinal), "access key should not match");
                            V2TestSupport.ValidateBase64Signature(fields.Signature);
                        }
                    }),
                    Case("V2Validation", "MalformedAuthorizationHeaderFailsParsing", "Malformed Authorization header fails before signature comparison", () =>
                    {
                        V2TestSupport.AssertThrows<FormatException>(() =>
                            V2TestSupport.ParseAuthorizationHeader("Bearer not-a-v2-header"));
                    }),
                    Case("V2Validation", "MalformedSignedUrlFailsParsing", "Signed URL missing Signature fails parsing", () =>
                    {
                        V2TestSupport.AssertThrows<FormatException>(() =>
                            V2TestSupport.ParseSignedUrl("https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIDEXAMPLE&Expires=1175139620"));
                    }),
                    Case("V2Validation", "MalformedSignedUrlBase64FailsParsing", "Signed URL with malformed Base64 signature fails parsing", () =>
                    {
                        V2TestSupport.AssertThrows<FormatException>(() =>
                            V2TestSupport.ParseSignedUrl("https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?AWSAccessKeyId=AKIDEXAMPLE&Expires=1175139620&Signature=not-base64"));
                    }),
                    Case("V2Validation", "WrongButParseableSignatureFailsComparison", "Parseable but incorrect Base64 signature does not validate", () =>
                    {
                        string wrongSignature = "AAAAAAAAAAAAAAAAAAAAAAAAAAA=";
                        V2TestSupport.ValidateBase64Signature(wrongSignature);

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(wrongSignature, result.Signature, StringComparison.Ordinal), "wrong signature should not match");
                        }
                    }),
                    Case("V2Validation", "ChangedPathChangesSignature", "Changing the path changes the signature", () =>
                    {
                        using (V2SignatureResult first = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        using (V2SignatureResult second = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/kitten.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "path change should change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedDateChangesSignature", "Changing the Date header changes the signature", () =>
                    {
                        NameValueCollection firstHeaders = V2TestSupport.HeadersWithDate();
                        NameValueCollection secondHeaders = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "Date", "Wed, 28 Mar 2007 19:36:42 +0000" }
                        };

                        using (V2SignatureResult first = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            firstHeaders))
                        using (V2SignatureResult second = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            secondHeaders))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "date change should change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedSignedHeaderChangesSignature", "Changing a signed x-amz header changes the signature", () =>
                    {
                        NameValueCollection firstHeaders = V2TestSupport.HeadersWithDate();
                        firstHeaders.Add("x-amz-meta-color", "blue");

                        NameValueCollection secondHeaders = V2TestSupport.HeadersWithDate();
                        secondHeaders.Add("x-amz-meta-color", "red");

                        using (V2SignatureResult first = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            firstHeaders))
                        using (V2SignatureResult second = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            secondHeaders))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "signed header change should change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedUnsignedHeaderDoesNotChangeSignature", "Changing an unsigned ordinary header does not change the signature", () =>
                    {
                        NameValueCollection firstHeaders = V2TestSupport.HeadersWithDate();
                        firstHeaders.Add("x-custom-header", "one");

                        NameValueCollection secondHeaders = V2TestSupport.HeadersWithDate();
                        secondHeaders.Add("x-custom-header", "two");

                        using (V2SignatureResult first = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            firstHeaders))
                        using (V2SignatureResult second = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            secondHeaders))
                        {
                            V2TestSupport.AssertEqual(first.Signature, second.Signature, "unsigned header should not change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedHttpMethodChangesSignature", "Changing the HTTP method changes the signature", () =>
                    {
                        using (V2SignatureResult first = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        using (V2SignatureResult second = new V2SignatureResult(
                            "PUT",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "method change should change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedSignedUrlExpirationChangesSignature", "Changing signed URL expiration changes the signature", () =>
                    {
                        using (V2SignedUrlResult first = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        using (V2SignedUrlResult second = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139621))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "expiration change should change signature");
                        }
                    }),
                    Case("V2Validation", "ChangedSignedUrlSubresourceChangesSignature", "Changing signed URL subresources changes the signature", () =>
                    {
                        using (V2SignedUrlResult first = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?acl",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        using (V2SignedUrlResult second = new V2SignedUrlResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg?versionId=abc",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620))
                        {
                            V2TestSupport.AssertTrue(!String.Equals(first.Signature, second.Signature, StringComparison.Ordinal), "subresource change should change signature");
                        }
                    })
                });
        }

        /// <summary>
        /// Public API surface behavior suite.
        /// </summary>
        /// <returns>Touchstone test suite.</returns>
        public static TestSuiteDescriptor ApiSurfaceSuite()
        {
            return new TestSuiteDescriptor(
                suiteId: "V2ApiSurface",
                displayName: "AWS Signature Version 2 API Surface",
                cases: new List<TestCaseDescriptor>
                {
                    Case("V2ApiSurface", "HeaderResultUrlAndQueryProperties", "Header result exposes URL and query properties", () =>
                    {
                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "http://examplebucket.s3.amazonaws.com:8080/photos/puppy.jpg?acl&tag=a&tag=b",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        {
                            string[] tagValues = result.QueryElements.GetValues("tag");

                            V2TestSupport.AssertEqual("http", result.Protocol, "protocol");
                            V2TestSupport.AssertEqual(8080, result.Port, "port");
                            V2TestSupport.AssertEqual("examplebucket.s3.amazonaws.com", result.Hostname, "hostname");
                            V2TestSupport.AssertEqual("/photos/puppy.jpg", result.Path, "path");
                            V2TestSupport.AssertEqual("?acl&tag=a&tag=b", result.Querystring, "querystring");
                            V2TestSupport.AssertEqual(2, tagValues.Length, "tag count");
                            V2TestSupport.AssertEqual("a", tagValues[0], "first tag");
                            V2TestSupport.AssertEqual("b", tagValues[1], "second tag");
                        }
                    }),
                    Case("V2ApiSurface", "HeaderResultToStringAndDoubleDispose", "Header result ToString is V2-specific and double dispose is harmless", () =>
                    {
                        V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate());

                        string output = result.ToString();
                        V2TestSupport.AssertTrue(output.Contains("V2 Signature Result", StringComparison.Ordinal), "ToString should identify V2 signature result");
                        V2TestSupport.AssertTrue(output.Contains("Authorization header", StringComparison.Ordinal), "ToString should include authorization header");

                        result.Dispose();
                        result.Dispose();
                    }),
                    Case("V2ApiSurface", "SourceHeadersAreCopied", "Mutating source headers after construction does not change V2 signature fields", () =>
                    {
                        NameValueCollection headers = V2TestSupport.HeadersWithDate();

                        using (V2SignatureResult result = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            headers))
                        {
                            string signature = result.Signature;
                            headers.Set("Date", "Wed, 28 Mar 2007 19:36:42 +0000");

                            V2TestSupport.AssertEqual(V2TestSupport.Date, result.Date, "date");
                            V2TestSupport.AssertEqual(signature, result.Signature, "signature");
                        }
                    }),
                    Case("V2ApiSurface", "SignedUrlResultUrlAndToStringProperties", "Signed URL result exposes URL, expiration, and V2-specific ToString fields", () =>
                    {
                        using (V2SignedUrlResult result = new V2SignedUrlResult(
                            "GET",
                            "https://storage.example.com:9443/photos/puppy.jpg?partNumber=1",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            1175139620,
                            null,
                            "examplebucket"))
                        {
                            string output = result.ToString();

                            V2TestSupport.AssertEqual("https", result.Protocol, "protocol");
                            V2TestSupport.AssertEqual(9443, result.Port, "port");
                            V2TestSupport.AssertEqual("storage.example.com", result.Hostname, "hostname");
                            V2TestSupport.AssertEqual("/photos/puppy.jpg", result.Path, "path");
                            V2TestSupport.AssertEqual("?partNumber=1", result.Querystring, "querystring");
                            V2TestSupport.AssertEqual(DateTimeOffset.FromUnixTimeSeconds(1175139620), result.ExpiresAt, "expires at");
                            V2TestSupport.AssertEqual("/examplebucket/photos/puppy.jpg?partNumber=1", result.CanonicalizedResource, "canonical resource");
                            V2TestSupport.AssertTrue(output.Contains("V2 Signed URL Result", StringComparison.Ordinal), "ToString should identify V2 signed URL result");
                            V2TestSupport.AssertTrue(output.Contains("Signed URL", StringComparison.Ordinal), "ToString should include signed URL");
                        }
                    }),
                    Case("V2ApiSurface", "V2AndV4TypesCanCoexist", "V2 and V4 result types can be used side by side", () =>
                    {
                        NameValueCollection v4Headers = new NameValueCollection(StringComparer.InvariantCultureIgnoreCase)
                        {
                            { "host", "example.com" }
                        };

                        using (V2SignatureResult v2 = new V2SignatureResult(
                            "GET",
                            "https://examplebucket.s3.amazonaws.com/photos/puppy.jpg",
                            V2TestSupport.AccessKey,
                            V2TestSupport.SecretKey,
                            V2TestSupport.HeadersWithDate()))
                        using (V4SignatureResult v4 = new V4SignatureResult(
                            "20150830T123600Z",
                            "GET",
                            "http://example.com/",
                            "key",
                            "secret",
                            "us-east-1",
                            "s3",
                            v4Headers))
                        {
                            V2TestSupport.AssertTrue(v2.AuthorizationHeader.StartsWith("AWS ", StringComparison.Ordinal), "V2 authorization header");
                            V2TestSupport.AssertTrue(v4.AuthorizationHeader.StartsWith("AWS4-HMAC-SHA256 ", StringComparison.Ordinal), "V4 authorization header");
                        }
                    })
                });
        }

        private static TestCaseDescriptor Case(string suiteId, string caseId, string displayName, Action action)
        {
            return new TestCaseDescriptor(
                suiteId: suiteId,
                caseId: caseId,
                displayName: "V2 - " + displayName,
                executeAsync: cancellationToken =>
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    action();
                    return Task.CompletedTask;
                });
        }
    }
}
