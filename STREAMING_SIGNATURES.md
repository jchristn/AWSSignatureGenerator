# Streaming Signature Enhancements for AWSSignatureGenerator

## Background

AWSSDK 4.x for .NET sends all PUT/POST requests with body content using **streaming signatures** rather than standard V4 signatures. This means any S3-compatible server using `AWSSignatureGenerator` for signature validation cannot validate uploads from AWSSDK 4.x clients.

### What AWSSDK 4.x sends

```
PUT /bucket/key HTTP/1.1
Content-Length: 298
Content-Type: text/plain
Content-Encoding: aws-chunked
X-Amz-Content-SHA256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER
X-Amz-Decoded-Content-Length: 5
X-Amz-Trailer: x-amz-checksum-crc32
Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../20260402/us-east-1/s3/aws4_request,
  SignedHeaders=content-encoding;content-length;content-type;host;x-amz-content-sha256;
  x-amz-date;x-amz-decoded-content-length;x-amz-sdk-checksum-algorithm;x-amz-trailer,
  Signature=<seed-signature>

5;chunk-signature=<chunk-1-sig>
Hello
0;chunk-signature=<final-chunk-sig>

x-amz-checksum-crc32:<base64-crc32>
0;chunk-signature=<trailer-sig>

```

### What AWSSignatureGenerator supports today

The library currently computes standard V4 signatures where the entire payload is hashed upfront. The `V4PayloadHashEnum.IsStreaming` mode returns the literal string `"STREAMING-UNSIGNED-PAYLOAD-TRAILER"` for the payload hash, but no actual chunk signature computation exists.

## Proposed Enhancements

### 1. Seed Signature Validation

**Priority: High** - This is the minimum needed to validate AWSSDK 4.x uploads.

The seed signature in the `Authorization` header of a streaming request is a standard V4 signature where the payload hash is the literal string `STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER` (or `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` without trailers). The canonical request is built exactly like a normal V4 request, except the `HashedPayload` is this literal string instead of the SHA256 of the body.

**What to add:**

Add a new `V4PayloadHashEnum` value and update the payload hash logic:

```csharp
public enum V4PayloadHashEnum
{
    IsStreaming,                  // existing: "STREAMING-UNSIGNED-PAYLOAD-TRAILER"
    Unsigned,                    // existing: "UNSIGNED-PAYLOAD"
    Signed,                      // existing: computed SHA256
    StreamingSigned,             // new: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"
    StreamingSignedTrailer       // new: "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER"
}
```

When `StreamingSigned` or `StreamingSignedTrailer` is selected, `HashedPayload` returns the corresponding literal string. The resulting `Signature` is the **seed signature** that can be compared against the `Authorization` header's `Signature` field.

**How S3Server would use it:**

```csharp
// Detect streaming mode from x-amz-content-sha256 header
string contentSha256 = request.RetrieveHeaderValue("x-amz-content-sha256");

V4PayloadHashEnum hashMode = contentSha256 switch
{
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER" => V4PayloadHashEnum.StreamingSignedTrailer,
    "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"         => V4PayloadHashEnum.StreamingSigned,
    "UNSIGNED-PAYLOAD"                           => V4PayloadHashEnum.Unsigned,
    _                                            => V4PayloadHashEnum.Signed
};

V4SignatureResult result = new V4SignatureResult(
    timestamp, method, url, accessKey, secretKey, region, "s3",
    headers, null, hashMode);  // null body - not hashed for streaming

if (!result.Signature.Equals(requestSignature))
    throw new S3Exception(new Error(ErrorCode.SignatureDoesNotMatch));
```

This is the simplest enhancement and unblocks AWSSDK 4.x compatibility for S3Server. The seed signature validates the request headers and proves the client has the correct credentials. Individual chunk signatures (below) provide payload integrity but are not strictly required for auth.

### 2. Chunk Signature Computation

**Priority: Medium** - Needed for full payload integrity validation.

AWS streaming signatures use a chained HMAC scheme. Each chunk's signature depends on the previous chunk's signature (or the seed signature for the first chunk).

**Wire format of each chunk:**

```
<hex-size>;chunk-signature=<signature>\r\n
<chunk-data>\r\n
```

**Final chunk (empty body):**

```
0;chunk-signature=<signature>\r\n
\r\n
```

**Chunk signature algorithm:**

```
StringToSign =
    "AWS4-HMAC-SHA256-PAYLOAD" + "\n" +
    timestamp + "\n" +
    date/region/service/aws4_request + "\n" +
    previous-signature + "\n" +                    // seed sig for first chunk
    SHA256("") + "\n" +                            // hash of empty string (constant)
    SHA256(chunk-data)                             // hash of this chunk's data

chunk-signature = Hex(HMAC-SHA256(signing-key, StringToSign))
```

**What to add:**

A new class `V4ChunkSigner` that takes the signing key and seed signature, then validates chunks incrementally:

```csharp
public class V4ChunkSigner : IDisposable
{
    /// <summary>
    /// Instantiate.
    /// </summary>
    /// <param name="timestamp">Request timestamp in yyyyMMddTHHmmssZ format.</param>
    /// <param name="region">AWS region.</param>
    /// <param name="service">AWS service.</param>
    /// <param name="signingKey">Derived signing key bytes from V4SignatureResult.</param>
    /// <param name="seedSignature">Seed signature from the Authorization header.</param>
    public V4ChunkSigner(
        string timestamp,
        string region,
        string service,
        byte[] signingKey,
        string seedSignature);

    /// <summary>
    /// Compute the expected signature for the next chunk.
    /// Call this for each chunk in order, including the final zero-length chunk.
    /// </summary>
    /// <param name="chunkData">Chunk data bytes. Empty/null for the final chunk.</param>
    /// <returns>Expected hex signature for this chunk.</returns>
    public string ComputeChunkSignature(byte[] chunkData);

    /// <summary>
    /// Validate a chunk's signature.
    /// </summary>
    /// <param name="chunkData">Chunk data bytes.</param>
    /// <param name="providedSignature">Signature from the chunk header.</param>
    /// <returns>True if signature matches.</returns>
    public bool ValidateChunk(byte[] chunkData, string providedSignature);
}
```

**Usage pattern:**

```csharp
V4ChunkSigner signer = new V4ChunkSigner(
    timestamp, region, "s3",
    result.SigningKeyBytes,   // new property exposing raw key bytes
    seedSignature);

// For each chunk read from the stream:
while (!isFinal)
{
    (byte[] data, string sig, bool final) = ReadNextChunk(stream);
    if (!signer.ValidateChunk(data, sig))
        throw new S3Exception(new Error(ErrorCode.SignatureDoesNotMatch));
    isFinal = final;
}
```

### 3. Trailer Signature Computation

**Priority: Low** - Only needed for full CRC/checksum trailer validation.

When `X-Amz-Trailer` is present, after the final zero-length chunk, the client sends trailing headers followed by a trailer signature chunk.

**Wire format:**

```
0;chunk-signature=<final-chunk-sig>\r\n
\r\n
x-amz-checksum-crc32:<base64-value>\r\n
\r\n
0;chunk-signature=<trailer-sig>\r\n
\r\n
```

**Trailer signature algorithm:**

```
StringToSign =
    "AWS4-HMAC-SHA256-TRAILER" + "\n" +
    timestamp + "\n" +
    date/region/service/aws4_request + "\n" +
    previous-signature + "\n" +
    SHA256(trailing-headers)             // canonical trailing headers

trailing-headers = lowercase(header-name) + ":" + trim(header-value) + "\n"
```

**What to add:**

Extend `V4ChunkSigner` with a trailer validation method:

```csharp
/// <summary>
/// Compute the expected signature for the trailing headers.
/// Call this after the final zero-length chunk has been processed.
/// </summary>
/// <param name="trailerHeaders">Trailing headers as key-value pairs, sorted by key.</param>
/// <returns>Expected hex signature for the trailer.</returns>
public string ComputeTrailerSignature(SortedDictionary<string, string> trailerHeaders);

/// <summary>
/// Validate the trailer signature.
/// </summary>
/// <param name="trailerHeaders">Trailing headers.</param>
/// <param name="providedSignature">Signature from the trailer chunk.</param>
/// <returns>True if signature matches.</returns>
public bool ValidateTrailer(SortedDictionary<string, string> trailerHeaders, string providedSignature);
```

### 4. Expose Signing Key Bytes

**Priority: High** - Required by the chunk signer.

`V4SignatureResult` currently computes the signing key internally and only exposes it as a hex string via `SigningKey`. The chunk signer needs the raw bytes.

**What to add:**

```csharp
/// <summary>
/// Signing key as raw bytes.
/// Used by V4ChunkSigner for chunk signature computation.
/// </summary>
public byte[] SigningKeyBytes { get; }
```

This property should expose the already-computed `_SigningKey` byte array.

### 5. AWS Chunked Stream Parser

**Priority: Medium** - Convenience class for reading aws-chunked encoded streams.

A helper that reads an aws-chunked encoded stream and yields individual chunks with their signatures:

```csharp
public class AwsChunkedStreamReader : IDisposable
{
    /// <summary>
    /// Instantiate.
    /// </summary>
    /// <param name="stream">Input stream containing aws-chunked encoded data.</param>
    public AwsChunkedStreamReader(Stream stream);

    /// <summary>
    /// Read the next chunk from the stream.
    /// </summary>
    /// <param name="token">Cancellation token.</param>
    /// <returns>Chunk result with data, signature, and whether this is the final chunk.</returns>
    public async Task<AwsChunkResult> ReadNextChunkAsync(CancellationToken token = default);
}

public class AwsChunkResult
{
    /// <summary>Chunk data bytes. Empty for the final chunk.</summary>
    public byte[] Data { get; set; }

    /// <summary>Chunk signature from the chunk header.</summary>
    public string Signature { get; set; }

    /// <summary>True if this is the final (zero-length) chunk.</summary>
    public bool IsFinal { get; set; }

    /// <summary>Trailing headers, if present after the final chunk.</summary>
    public SortedDictionary<string, string> TrailerHeaders { get; set; }

    /// <summary>Trailer signature, if present.</summary>
    public string TrailerSignature { get; set; }
}
```

## Implementation Order

| Phase | Enhancement | Unblocks |
|-------|-------------|----------|
| 1     | Seed signature validation (new enum values) | AWSSDK 4.x auth validation in S3Server |
| 1     | Expose `SigningKeyBytes` property | Phase 2 |
| 2     | `V4ChunkSigner` class | Full payload integrity validation |
| 2     | `AwsChunkedStreamReader` class | Easy chunk parsing for consumers |
| 3     | Trailer signature support in `V4ChunkSigner` | CRC/checksum trailer validation |

Phase 1 is a small change (~20 lines) and immediately unblocks S3Server's signature validation with AWSSDK 4.x. Phases 2 and 3 provide defense-in-depth payload integrity.

## References

- [AWS SigV4 Streaming](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html)
- [AWS SigV4 Chunked Upload](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html#sigv4-chunked-body-definition)
- [AWS SigV4 Trailing Headers](https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming-trailers.html)
- [AWSSDK.S3 4.x Source](https://github.com/aws/aws-sdk-net)
