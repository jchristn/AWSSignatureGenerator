![alt tag](https://github.com/jchristn/AWSSignatureGenerator/raw/main/Assets/icon.ico)

# AWSSignatureGenerator

Library for generating AWS V4 signatures.  This library has not been tested comprehensively; bugs likely exist.  Multiple examples of AWS V4 signature generation exists in random places and seemingly all of them have issues.  This code was built using the AWS CLI and boto as a reference.

[![NuGet Version](https://img.shields.io/nuget/v/AWSSignatureGenerator.svg?style=flat)](https://www.nuget.org/packages/AWSSignatureGenerator/) [![NuGet](https://img.shields.io/nuget/dt/AWSSignatureGenerator.svg)](https://www.nuget.org/packages/AWSSignatureGenerator) 

## Feedback and Enhancements

Encounter an issue or have an enhancement request?  Please file an issue or start a discussion here!

## New in v1.0.x

- Initial release supporting V4 signatures

## Examples

Refer to the ```Test``` project for a full examples.

```csharp
using AWSSignatureGenerator;

NameValueCollection headers = new NameValueCollection
{
  { "Host", "localhost:8000" },
  { "x-amz-content-sha256", "[sha256 hash, lowercase hex string" },
  { "x-amz-date", "20231109T012345Z" }
};

V4SignatureResult result = new V4SignatureResult(
  "20231109T012345Z",           // timestamp, of the form yyyyMMddTHHmmssZ
  "GET",                        // HTTP method
  "http://localhost:8000/",     // URL
  "AKIAIOSFODNN7EXAMPLE",       // access key
  "wJalrXU...EXAMPLEKEY",       // secret key
  "us-west-1",                  // region
  "s3",                         // service
  headers,                      // request headers
  body,                         // request body, string, byte[], or Stream
  V4PayloadHashEnum.Signed      // Signed, IsStreaming, Unsigned
  );

Console.WriteLine("Signature            : " + result.Signature);
Console.WriteLine("Authorization header : " + result.AuthorizationHeader);
```

## Version History

Refer to CHANGELOG.md for details.
