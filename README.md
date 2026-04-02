![alt tag](https://github.com/jchristn/AWSSignatureGenerator/raw/main/Assets/icon.ico)

# AWSSignatureGenerator

A .NET class library for generating and validating AWS V4 signatures, including streaming (chunked) signatures used by AWSSDK 4.x. Built using the AWS CLI and boto as a reference implementation.

[![NuGet Version](https://img.shields.io/nuget/v/AWSSignatureGenerator.svg?style=flat)](https://www.nuget.org/packages/AWSSignatureGenerator/) [![NuGet](https://img.shields.io/nuget/dt/AWSSignatureGenerator.svg)](https://www.nuget.org/packages/AWSSignatureGenerator) 

## Feedback and Enhancements

Encounter an issue or have an enhancement request? Please file an issue or start a discussion here!

## New in v1.0.x

- Initial release supporting V4 signatures
- Streaming signature support: seed signature validation, chunk signature computation, trailer signature validation
- `V4ChunkSigner` for validating aws-chunked upload payloads
- `AwsChunkedStreamReader` for parsing aws-chunked encoded streams
- `SigningKeyBytes` property for accessing raw signing key bytes

## Standard V4 Signatures

Use `V4SignatureResult` to generate a standard V4 signature for any AWS request. This is the most common use case — signing or validating a request where the entire payload is available upfront.

```csharp
using AWSSignatureGenerator;

NameValueCollection headers = new NameValueCollection
{
    { "Host", "examplebucket.s3.amazonaws.com" },
    { "x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "x-amz-date", "20231109T012345Z" }
};

V4SignatureResult result = new V4SignatureResult(
    "20231109T012345Z",           // timestamp, of the form yyyyMMddTHHmmssZ
    "GET",                        // HTTP method
    "https://examplebucket.s3.amazonaws.com/test.txt",
    "AKIAIOSFODNN7EXAMPLE",       // access key
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", // secret key
    "us-east-1",                  // region
    "s3",                         // service
    headers,                      // request headers (must include "host")
    null,                         // request body: string, byte[], or Stream
    V4PayloadHashEnum.Signed      // payload hashing mode
);

Console.WriteLine("Signature            : " + result.Signature);
Console.WriteLine("Authorization header : " + result.AuthorizationHeader);
```

### Payload Hashing Modes

| Mode | When to Use |
|------|-------------|
| `Signed` | Default. Computes SHA-256 of the request body. Use for standard requests where the full payload is available. |
| `Unsigned` | Payload hash is the literal `UNSIGNED-PAYLOAD`. Use when the server does not require payload signing (e.g. presigned URLs). |
| `IsStreaming` | Payload hash is the literal `STREAMING-UNSIGNED-PAYLOAD-TRAILER`. Use for unsigned streaming uploads. |
| `StreamingSigned` | Payload hash is the literal `STREAMING-AWS4-HMAC-SHA256-PAYLOAD`. Use for AWSSDK 4.x chunked uploads without trailing checksums. |
| `StreamingSignedTrailer` | Payload hash is the literal `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER`. Use for AWSSDK 4.x chunked uploads with trailing checksums (e.g. CRC32). |

### Request Body Types

The `requestBody` parameter accepts `string`, `byte[]`, or `Stream`. When using `Signed` mode, the body is hashed to produce the payload hash. For all other modes, the body parameter is ignored (pass `null`).

```csharp
// String body
V4SignatureResult result = new V4SignatureResult(timestamp, "PUT", url, accessKey, secretKey,
    region, "s3", headers, "Hello World", V4PayloadHashEnum.Signed);

// Byte array body
byte[] body = Encoding.UTF8.GetBytes("Hello World");
V4SignatureResult result = new V4SignatureResult(timestamp, "PUT", url, accessKey, secretKey,
    region, "s3", headers, body, V4PayloadHashEnum.Signed);

// Stream body (position is reset after hashing)
using FileStream fs = File.OpenRead("largefile.bin");
V4SignatureResult result = new V4SignatureResult(timestamp, "PUT", url, accessKey, secretKey,
    region, "s3", headers, fs, V4PayloadHashEnum.Signed);
```

## Streaming Signatures (AWSSDK 4.x)

AWSSDK 4.x for .NET sends PUT/POST requests with body content using **streaming (chunked) signatures** rather than standard V4 signatures. The library provides full support for validating these requests.

A streaming signature request has three layers of validation:

1. **Seed signature** — validates the request headers (proves the client has correct credentials)
2. **Chunk signatures** — validates each chunk of payload data (provides payload integrity)
3. **Trailer signature** — validates trailing headers like checksums (optional, only when `X-Amz-Trailer` is present)

### Step 1: Validate the Seed Signature

The seed signature is a standard V4 signature where the payload hash is a literal string (not the hash of the body). Detect the mode from the `x-amz-content-sha256` header:

```csharp
// Detect streaming mode from the x-amz-content-sha256 header
string contentSha256 = request.Headers["x-amz-content-sha256"];

V4PayloadHashEnum hashMode = contentSha256 switch
{
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => V4PayloadHashEnum.StreamingSignedTrailer,
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"         => V4PayloadHashEnum.StreamingSigned,
    "UNSIGNED-PAYLOAD"                           => V4PayloadHashEnum.Unsigned,
    _                                            => V4PayloadHashEnum.Signed
};

V4SignatureResult seedResult = new V4SignatureResult(
    timestamp, method, url, accessKey, secretKey, region, "s3",
    headers, null, hashMode);  // null body — not hashed for streaming

// Compare against the Signature field in the Authorization header
if (!seedResult.Signature.Equals(requestSignature))
    throw new Exception("Seed signature does not match");
```

### Step 2: Validate Chunk Signatures

Use `V4ChunkSigner` to validate each chunk as it arrives. The signer chains signatures — each chunk's signature depends on the previous one.

```csharp
using V4ChunkSigner signer = new V4ChunkSigner(
    timestamp,                    // same timestamp as the request
    region,                       // e.g. "us-east-1"
    "s3",                         // service
    seedResult.SigningKeyBytes,   // raw signing key bytes
    seedResult.Signature);        // seed signature

// For each chunk read from the stream:
while (true)
{
    // Read the next chunk (your code to parse the wire format)
    (byte[] data, string sig, bool isFinal) = ReadNextChunk(stream);

    if (!signer.ValidateChunk(data, sig))
        throw new Exception("Chunk signature does not match");

    if (isFinal) break;
}
```

### Step 3: Validate Trailer Signature (Optional)

When the request includes `X-Amz-Trailer`, trailing headers (e.g. `x-amz-checksum-crc32`) are sent after the final chunk, followed by a trailer signature.

```csharp
// After validating all chunks including the final zero-length chunk:
SortedDictionary<string, string> trailerHeaders = new SortedDictionary<string, string>
{
    { "x-amz-checksum-crc32", checksumValue }
};

if (!signer.ValidateTrailer(trailerHeaders, trailerSignature))
    throw new Exception("Trailer signature does not match");
```

### Parsing aws-chunked Streams

Use `AwsChunkedStreamReader` to parse the aws-chunked wire format. This handles the chunk framing so you don't have to.

```csharp
using AwsChunkedStreamReader reader = new AwsChunkedStreamReader(requestBodyStream);
using V4ChunkSigner signer = new V4ChunkSigner(
    timestamp, region, "s3", seedResult.SigningKeyBytes, seedResult.Signature);

while (true)
{
    AwsChunkResult chunk = await reader.ReadNextChunkAsync();
    if (chunk == null) break;

    if (chunk.Signature != null)
    {
        if (!signer.ValidateChunk(chunk.Data, chunk.Signature))
            throw new Exception("Chunk signature mismatch");
    }

    if (chunk.IsFinal)
    {
        // Check for trailing headers
        AwsChunkResult trailer = await reader.ReadNextChunkAsync();
        if (trailer?.TrailerHeaders != null && trailer.TrailerSignature != null)
        {
            if (!signer.ValidateTrailer(trailer.TrailerHeaders, trailer.TrailerSignature))
                throw new Exception("Trailer signature mismatch");
        }
        break;
    }

    // Process chunk.Data (write to file, etc.)
}
```

### Wire Format Reference

AWSSDK 4.x sends chunked uploads in this format:

```
<hex-chunk-size>;chunk-signature=<signature>\r\n
<chunk-data>\r\n
...
0;chunk-signature=<final-signature>\r\n
\r\n
x-amz-checksum-crc32:<base64-value>\r\n    (if trailers present)
\r\n
0;chunk-signature=<trailer-signature>\r\n  (if trailers present)
\r\n
```

## API Reference

### V4SignatureResult

The main class for generating standard and seed signatures.

| Property | Type | Description |
|----------|------|-------------|
| `Signature` | `string` | Final V4 signature as lowercase hex |
| `AuthorizationHeader` | `string` | Complete `Authorization` header value |
| `SigningKeyBytes` | `byte[]` | Raw signing key bytes (needed by `V4ChunkSigner`) |
| `SigningKey` | `string` | Signing key as lowercase hex |
| `HashedPayload` | `string` | Payload hash (computed or literal, depending on mode) |
| `CanonicalRequest` | `string` | Full canonical request string |
| `StringToSign` | `string` | String to sign |
| `SignedHeaders` | `List<string>` | Sorted list of signed header names |

### V4ChunkSigner

Computes and validates streaming chunk and trailer signatures.

| Method | Returns | Description |
|--------|---------|-------------|
| `ComputeChunkSignature(byte[] chunkData)` | `string` | Compute expected signature for the next chunk |
| `ValidateChunk(byte[] chunkData, string providedSignature)` | `bool` | Validate a chunk's signature |
| `ComputeTrailerSignature(SortedDictionary<string, string> trailerHeaders)` | `string` | Compute expected trailer signature |
| `ValidateTrailer(SortedDictionary<string, string> trailerHeaders, string providedSignature)` | `bool` | Validate the trailer signature |

### AwsChunkedStreamReader

Reads aws-chunked encoded streams and yields `AwsChunkResult` objects.

| Method | Returns | Description |
|--------|---------|-------------|
| `ReadNextChunkAsync(CancellationToken token)` | `Task<AwsChunkResult>` | Read the next chunk from the stream |

### AwsChunkResult

| Property | Type | Description |
|----------|------|-------------|
| `Data` | `byte[]` | Chunk data (empty for final chunk) |
| `Signature` | `string` | Chunk signature |
| `IsFinal` | `bool` | True if this is the final zero-length chunk |
| `TrailerHeaders` | `SortedDictionary<string, string>` | Trailing headers (if present) |
| `TrailerSignature` | `string` | Trailer signature (if present) |

## Version History

Refer to CHANGELOG.md for details.
