# V2 Signature Support Plan

Draft date: 2026-06-11

## Objective

Add AWS Signature Version 2 support to AWSSignatureGenerator as an additive, low-risk product update that preserves every existing V4 workflow and V4-specific public class.

The primary product target is Amazon S3 Signature Version 2:

- REST `Authorization` header signing.
- Query-string authentication, also known as signed URLs or presigned URLs.
- The key S3 SigV2 fields: `Content-MD5`, `Content-Type`, `Date` or `Expires`, `CanonicalizedAmzHeaders`, `CanonicalizedResource`, `AWSAccessKeyId`, and `Signature`.

Secondary consideration: AWS Query API Signature Version 2 for legacy services such as SimpleDB or older CloudSearch-style APIs. This is related, but it is not the same algorithm shape as S3 SigV2. It should be either a separate phase or a separate public type so S3 behavior stays crisp and predictable.

## Source References

Use primary AWS references while implementing and reviewing:

- Amazon S3 SigV2 overview: https://docs.aws.amazon.com/AmazonS3/latest/API/S3_Authentication2.html
- Amazon S3 SigV2 appendix and deprecation note: https://docs.aws.amazon.com/AmazonS3/latest/API/Appendix-Sigv2.html
- S3 signature-version status and migration guidance: https://docs.aws.amazon.com/AmazonS3/latest/API/specify-signature-version.html
- AWS Query API SigV2 example, SimpleDB: https://docs.aws.amazon.com/AmazonSimpleDB/latest/DeveloperGuide/HMACAuth.html

Implementation note: S3 SigV2 is deprecated for AWS S3 and unsupported in many current AWS S3 scenarios. This support exists for legacy AWS S3 compatibility, old presigned URL compatibility, and S3-compatible systems that still require SigV2.

## Versioning Strategy

Goal: increment the minor version number for the additive V2 support release.

- Planned package version: `1.1.0`, assuming the current package version remains `1.0.12`.
- If the current package version changes before this work ships, use the next minor version from that baseline.
- No major-version changes.
- No breaking changes.
- No changes to existing V4 constructor signatures, public properties, enum values, or output formatting.
- No changes to existing V4 expected signatures unless a separate bug fix is explicitly approved.

Release gate:

- [x] Existing V4 tests pass unchanged.
- [x] New V2 tests pass.
- [x] Release build runs after all tests pass.
- [x] README and package metadata accurately describe V2 as legacy/deprecated support.
- [x] No user code currently using `V4SignatureResult`, `V4ChunkSigner`, `V4PayloadHashEnum`, or `AwsChunkedStreamReader` needs to change.

## Code Style and Repository Requirements

All implementation work must follow the local requirements in `C:\Code\Agents\requirements`, especially `CODE_STYLE.md`, `BACKEND_TEST_ARCHITECTURE.md`, `REPOSITORY_REQUIREMENTS.md`, and `WRITING_DOCUMENTS.md`. Treat these as release gates, not preferences. If an existing file has older style, avoid broad churn, but every newly added or materially changed file for this work should follow the current requirements.

Code style gates:

- [x] Do not use `var`; declare variables with explicit concrete types.
- [x] Do not use tuples or `ValueTuple` return values. Use named classes or explicit descriptor objects instead.
- [x] Keep namespace declarations at the top of C# files and put `using` statements inside the namespace block.
- [x] Sort Microsoft and `System.*` usings first, alphabetically, followed by non-System usings alphabetically.
- [x] Keep one class or one enum per file. Do not add nested or multi-type files.
- [x] Use private field names with underscore plus PascalCase, for example `_SigningKey`.
- [x] Add XML documentation for every public type, public member, constructor, and public method.
- [x] Do not add XML documentation to private members or private methods.
- [x] Use explicit backing fields for public members that validate null, ranges, defaults, minimums, or maximums.
- [x] Document defaults, ranges, nullability, thread-safety expectations, and public exceptions where applicable.
- [x] Use specific exception types with contextual error messages. Do not throw generic `Exception` from library code.
- [x] Use guard clauses at the start of public constructors and methods.
- [x] Enable nullable reference types in new projects and new test projects where feasible.
- [x] Disable implicit usings in new projects unless the repository owner explicitly approves otherwise.
- [x] Use `.ConfigureAwait(false)` for async calls where appropriate.
- [x] Async methods must accept a `CancellationToken` unless the owning type already carries one.
- [x] Async methods must check cancellation at appropriate points.
- [x] Implement the full dispose pattern for any type that owns disposable resources.
- [x] Do not add `Console.WriteLine` or other console output to library code or `Test.Shared`.
- [x] README and other docs touched by the work must be reviewed for accuracy before release.
- [x] Compile with no new warnings to the best extent possible.

Test style gates:

- [x] `Test.Shared` follows Touchstone descriptor patterns and contains no runner-specific framework attributes.
- [x] `Test.Shared` references only `AWSSignatureGenerator` and `Touchstone.Core`.
- [x] `Test.Shared` performs assertions by throwing specific exceptions with useful messages.
- [x] Runner projects may contain runner glue only; no AWS signature assertions or fixtures belong there.
- [x] Console output is owned by `Test.Automated` through Touchstone CLI behavior, not by shared test definitions.

## Product Scope

### In Scope for Initial Release

- [x] S3 SigV2 REST header signing.
- [x] S3 SigV2 signed URL generation.
- [x] S3 SigV2 server-side validation workflow by recomputing and comparing `Signature`.
- [x] Virtual-hosted-style S3 URLs.
- [x] Path-style S3 URLs.
- [x] Custom S3-compatible endpoints where the bucket cannot be reliably inferred from the host.
- [x] Canonicalized `x-amz-*` header support, including temporary credential headers such as `x-amz-security-token`.
- [x] S3 subresource and response-header override canonicalization.
- [x] Official AWS documentation examples as golden tests where exact fixtures are available.
- [x] README examples for header signing and signed URLs.
- [x] Changelog and package metadata updates.

### Optional for Initial Release, Strongly Consider

- [x] Query-string preservation and parsing for temporary session tokens, including `x-amz-security-token`; automatic token injection remains out of scope for this release.
- [x] A small internal helper for common encoding and HMAC operations.
- [ ] Environment-gated integration tests against an S3-compatible SigV2 endpoint.

### Deferred or Out of Scope Unless Explicitly Approved

- [ ] Browser-based POST policy signing for S3 SigV2.
- [ ] Changing `V4SignatureResult` internals for shared helper reuse.
- [ ] Adding a single "signature version" switch to existing V4 APIs.
- [ ] Automatically choosing V2 or V4 based on endpoint or region.
- [ ] Guaranteeing SigV2 works against modern AWS S3 buckets or regions where AWS has disabled SigV2.
- [ ] Broad compatibility promises for every third-party S3-compatible product without product-specific tests.

## API Shape

Keep the geometry consistent with V4 by using result objects that expose the canonical inputs, string-to-sign, signature, and final header or URL. Do not fold V2 into `V4SignatureResult`.

### New S3 Header Signing Type

Add:

```csharp
namespace AWSSignatureGenerator
{
    public class V2SignatureResult : IDisposable
    {
        public string AccessKey { get; }
        public string SecretKey { get; }
        public string HttpMethod { get; }
        public string FullUrl { get; }
        public string Protocol { get; }
        public int Port { get; }
        public string Hostname { get; }
        public string Path { get; }
        public string Querystring { get; }
        public NameValueCollection QueryElements { get; }
        public NameValueCollection Headers { get; }

        public string ContentMd5 { get; }
        public string ContentType { get; }
        public string Date { get; }
        public string DateElement { get; }
        public string CanonicalizedAmzHeaders { get; }
        public string CanonicalizedResource { get; }
        public string StringToSign { get; }
        public string Signature { get; }
        public string AuthorizationHeader { get; }

        public V2SignatureResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            NameValueCollection headers,
            string bucketName = null);
    }
}
```

Reasoning:

- V2 header signing uses the actual request `Date` header or an `x-amz-date` header. Taking the headers as source of truth avoids mismatches during server-side validation.
- `bucketName` is optional. It is needed for custom domains, CNAMEs, and S3-compatible endpoints where the bucket cannot be inferred safely from the host.
- No `Region`, `Service`, `PayloadHash`, `SigningKey`, or `SigningKeyBytes` properties. Those are V4 concepts and should not appear on V2 types.

Expected use:

```csharp
NameValueCollection headers = new NameValueCollection
{
    { "Host", "johnsmith.s3.amazonaws.com" },
    { "Date", "Tue, 27 Mar 2007 19:36:42 +0000" }
};

using V2SignatureResult result = new V2SignatureResult(
    "GET",
    "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg",
    accessKey,
    secretKey,
    headers);

Console.WriteLine(result.Signature);
Console.WriteLine(result.AuthorizationHeader);
```

### New S3 Signed URL Type

Add:

```csharp
namespace AWSSignatureGenerator
{
    public class V2SignedUrlResult : IDisposable
    {
        public string AccessKey { get; }
        public string SecretKey { get; }
        public string HttpMethod { get; }
        public string FullUrl { get; }
        public string Protocol { get; }
        public int Port { get; }
        public string Hostname { get; }
        public string Path { get; }
        public string Querystring { get; }
        public NameValueCollection QueryElements { get; }
        public NameValueCollection Headers { get; }

        public long Expires { get; }
        public DateTimeOffset ExpiresAt { get; }
        public string ContentMd5 { get; }
        public string ContentType { get; }
        public string CanonicalizedAmzHeaders { get; }
        public string CanonicalizedResource { get; }
        public string StringToSign { get; }
        public string Signature { get; }
        public string EncodedSignature { get; }
        public string SignedUrl { get; }

        public V2SignedUrlResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            long expires,
            NameValueCollection headers = null,
            string bucketName = null);

        public V2SignedUrlResult(
            string httpMethod,
            string fullUrl,
            string accessKey,
            string secretKey,
            DateTimeOffset expiresAt,
            NameValueCollection headers = null,
            string bucketName = null);
    }
}
```

Expected use:

```csharp
using V2SignedUrlResult result = new V2SignedUrlResult(
    "GET",
    "https://johnsmith.s3.amazonaws.com/photos/puppy.jpg",
    accessKey,
    secretKey,
    1175139620);

Console.WriteLine(result.SignedUrl);
```

### Optional AWS Query API Type

If support beyond S3 is included, add it as a separate type:

```csharp
public class V2QuerySignatureResult : IDisposable
{
    public string HttpMethod { get; }
    public string FullUrl { get; }
    public string Hostname { get; }
    public string Path { get; }
    public NameValueCollection Parameters { get; }
    public string SignatureMethod { get; }
    public string SignatureVersion { get; }
    public string CanonicalQuerystring { get; }
    public string StringToSign { get; }
    public string Signature { get; }
    public string SignedUrl { get; }
}
```

Keep this separate because AWS Query SigV2 signs:

```text
HTTPVerb + "\n" +
lowercase-host + "\n" +
path + "\n" +
canonicalized-query-string
```

That differs materially from S3 SigV2, which signs content headers, date or expiration, `x-amz-*` headers, and S3 canonical resources.

## Implementation Plan

### Phase 0: Baseline and Guardrails

- [x] Run current tests before any edits.
  - Command: `dotnet test src\AWSSignatureGenerator.sln`
  - Notes: Passed on 2026-06-11. Existing xUnit runner reported 82 passing tests for net8.0 and 82 passing tests for net10.0.
- [x] Record current public API surface for V4 classes.
  - Files: `V4SignatureResult.cs`, `V4ChunkSigner.cs`, `V4PayloadHashEnum.cs`.
  - Notes: V4 surface is being preserved; new V2 support is additive.
- [x] Confirm no V4 files need to be changed for the initial V2 feature.
  - Notes: V2 will be implemented through sibling classes and shared tests.
- [x] Review `C:\Code\Agents\requirements\CODE_STYLE.md` and `C:\Code\Agents\requirements\BACKEND_TEST_ARCHITECTURE.md` before implementation.
  - Notes: Style gates added to this plan, including no `var`, no tuples, Touchstone-backed shared tests, and runner-only test hosts.
- [x] Confirm the implementation approach avoids `var`, tuples, multi-type files, and runner-specific test logic in `Test.Shared`.
  - Notes: Implementation will use explicit local types, named classes, and Touchstone descriptors in `Test.Shared`.
- [ ] Create a branch or commit checkpoint before implementation.
  - Notes: Not applicable in this working session unless requested; worktree changes are being tracked through this plan and git status.

### Phase 1: Test Infrastructure Migration to Touchstone

Complete this before adding V2 implementation tests so all new coverage lands in the final runner-agnostic structure.

- [x] Add Touchstone NuGet package references, not Touchstone source project references.
  - Packages: `Touchstone.Core`, `Touchstone.Cli`, `Touchstone.XunitAdapter`, `Touchstone.NunitAdapter`.
  - Notes: Added NuGet package references at version `0.1.12`.
- [x] Set new test projects to disable implicit usings and enable nullable reference types where feasible.
  - Notes: Disabled implicit usings on the migrated/new test projects; nullable remains aligned with the existing project style to avoid broad warning churn.
- [x] Convert `Test.Shared` to Touchstone descriptors and suites.
  - Notes: Added `AwsSignatureSuites` and V2 Touchstone suites.
- [x] Convert existing V4 tests into shared Touchstone suites.
  - Notes: Existing V4 tests are wrapped by shared Touchstone descriptors without changing V4 assertions.
- [x] Convert `Test.Automated` to a Touchstone console runner.
  - Notes: `Program.cs` now calls `Touchstone.Cli.ConsoleRunner`.
- [x] Convert `Test.Xunit` to a Touchstone xUnit adapter runner.
  - Notes: xUnit runner now uses `TouchstoneTheoryData`.
- [x] Add `Test.Nunit` using the Touchstone NUnit adapter runner.
  - Notes: Added `Test.Nunit` with `TouchstoneTestCaseSource`.
- [x] Add `Test.Nunit` to `src\AWSSignatureGenerator.sln`.
  - Notes: Added through `dotnet sln`.
- [x] Verify all three runners execute the same shared test definitions.
  - Notes: After the V2 hardening pass, console, xUnit, and NUnit execute the same 160 shared tests per target framework.
- [x] Verify migrated test code contains no `var`, no tuples, and no `Console.WriteLine` in `Test.Shared`.
  - Notes: New/migrated Touchstone files use explicit local types; console output is limited to the Touchstone CLI runner package.

### Phase 2: Internal Helpers

Prefer local helper methods inside the new V2 classes unless duplication becomes painful. If extracting shared helpers, keep them `internal` and do not change V4 behavior.

- [x] Add `internal static class AwsSignatureEncoding` only if needed.
  - Candidate helpers: RFC 3986 query encode, URL decode, query parsing, stable sorting.
  - Notes: Implemented consolidated internal `V2S3Canonicalizer` helper for SigV2 S3 encoding, parsing, canonicalization, and HMAC-SHA1 signing.
- [x] Add `internal static class AwsSignatureCrypto` only if needed.
  - Candidate helpers: `HmacSha1`, `HmacSha256`, `Base64`, `Hex`.
  - Notes: HMAC-SHA1/Base64 support is contained in `V2S3Canonicalizer`; V4 crypto was not changed.
- [x] If V4 is changed to use helpers, prove byte-for-byte identical V4 output with tests before and after.
  - Notes: V4 helper code was not changed; existing V4 tests pass through Touchstone runners.
- [x] Verify helper code follows the style gates: explicit types, no tuples, one class per file, XML docs for public members only.
  - Notes: Style scan found no `var`, tuples, `ValueTuple`, or console output in new/migrated code.

### Phase 3: S3 SigV2 Header Signing

Add `src\AWSSignatureGenerator\V2SignatureResult.cs`.

Constructor and validation:

- [x] Validate `httpMethod` is non-empty.
- [x] Validate `fullUrl` is non-empty and absolute.
- [x] Validate `accessKey` is non-empty.
- [x] Validate `secretKey` is non-empty.
- [x] Accept `headers == null` by normalizing to an empty case-insensitive collection, matching the V4 style where possible.
- [x] Require enough date information for header signing:
  - `Date` header present, or
  - at least one canonical `x-amz-date` header present.
- [x] Preserve caller-provided header values exactly where the signature requires wire parity.
- [x] Uppercase `HttpMethod`, matching V4 behavior.
- [x] Parse raw path and raw query without losing encoded characters needed for canonical resource parity.

Core fields:

- [x] `ContentMd5`: value of `Content-MD5`, or empty string when absent.
- [x] `ContentType`: value of `Content-Type`, or empty string when absent.
- [x] `Date`: value of `Date`, or empty string when absent.
- [x] `DateElement`: empty string if any `x-amz-date` header is present; otherwise the `Date` value.
- [x] `CanonicalizedAmzHeaders`: normalized canonical string for all `x-amz-*` headers.
- [x] `CanonicalizedResource`: S3 canonical resource string.
- [x] `StringToSign`: exact S3 SigV2 string-to-sign.
- [x] `Signature`: Base64 HMAC-SHA1 of UTF-8 `StringToSign` using `SecretKey`.
- [x] `AuthorizationHeader`: `AWS {AccessKey}:{Signature}`.
- [x] `ToString()`: mirror V4 diagnostic style, but omit V4-only concepts.
- [x] `Dispose()`: present for shape consistency; no owned streams required.

String-to-sign:

```text
HTTP-Verb + "\n" +
Content-MD5 + "\n" +
Content-Type + "\n" +
DateElement + "\n" +
CanonicalizedAmzHeaders +
CanonicalizedResource
```

Do not add an extra blank line between `CanonicalizedAmzHeaders` and `CanonicalizedResource`; the canonicalized headers already include newlines when present.

### Phase 4: CanonicalizedAmzHeaders

Implement the S3 SigV2 `x-amz-*` header canonicalization rules.

- [x] Include every request header whose lower-case name starts with `x-amz-`.
- [x] Lowercase header names.
- [x] Sort by lowercase header name using ordinal ordering.
- [x] Combine duplicate header names into one line.
- [x] Preserve duplicate values in request order, matching the AWS S3 metadata example behavior.
- [x] Trim leading and trailing whitespace from values.
- [x] Normalize folded whitespace and repeated internal linear whitespace where required by the spec.
- [x] Format each line as `{lowercase-name}:{value}\n`.
- [x] Include `x-amz-security-token` when present.
- [x] Include `x-amz-date`; when present, `DateElement` must be empty.
- [x] Treat header lookup as case-insensitive.
- [x] Add tests for duplicate header names even if `NameValueCollection` stores them as comma-joined values.

Progress notes:

- Hardening pass added explicit tests for empty `x-amz-*` values, whitespace folding, duplicate value order, case-insensitive dates, sorted/lowercased header names, and the official CNAME metadata vector.

### Phase 5: CanonicalizedResource

Implement S3-specific canonical resource construction. This is the highest-risk area.

- [x] Preserve the raw request path enough to avoid changing significant encoded path characters.
- [x] Path-style URL:
  - `https://s3.amazonaws.com/bucket/key` signs as `/bucket/key`.
- [x] Virtual-hosted-style URL:
  - `https://bucket.s3.amazonaws.com/key` signs as `/bucket/key`.
- [x] Root bucket operation:
  - `https://bucket.s3.amazonaws.com/` signs as `/bucket/`.
- [x] Service root operation:
  - `https://s3.amazonaws.com/` signs as `/`.
- [x] Custom endpoint with explicit `bucketName`:
  - `https://storage.example.com/key`, `bucketName: photos`, signs as `/photos/key`.
- [x] CNAME endpoint with explicit `bucketName`:
  - `https://cdn.example.com/key`, `bucketName: photos`, signs as `/photos/key`.
- [x] Do not infer buckets from arbitrary custom hosts unless the rule is documented and tested.
- [x] Include only S3 subresources and response-header override query parameters in the canonical resource.
- [x] Sort included subresource parameters lexicographically by name.
- [x] Include subresources without values as `?acl`, not `?acl=`.
- [x] Include subresources with values as `?versionId=value`.
- [x] Exclude SigV2 auth query params from the canonical resource:
  - `AWSAccessKeyId`
  - `Expires`
  - `Signature`
- [x] Preserve existing query parameter encoding in a way that matches AWS expectations.

Canonical S3 subresource and override candidate list:

- [x] `acl`
- [x] `analytics`
- [x] `cors`
- [x] `delete`
- [x] `encryption`
- [x] `inventory`
- [x] `legal-hold`
- [x] `lifecycle`
- [x] `location`
- [x] `logging`
- [x] `metrics`
- [x] `notification`
- [x] `object-lock`
- [x] `partNumber`
- [x] `policy`
- [x] `publicAccessBlock`
- [x] `replication`
- [x] `requestPayment`
- [x] `restore`
- [x] `retention`
- [x] `tagging`
- [x] `torrent`
- [x] `uploadId`
- [x] `uploads`
- [x] `versionId`
- [x] `versioning`
- [x] `versions`
- [x] `website`
- [x] `response-cache-control`
- [x] `response-content-disposition`
- [x] `response-content-encoding`
- [x] `response-content-language`
- [x] `response-content-type`
- [x] `response-expires`

Before implementation, verify this list against current AWS S3 docs and keep a code comment with the source.

Progress notes:

- Hardening pass added coverage for regional, accelerate, and dualstack S3 hosts; service root; no-slash query URLs; encoded keys; literal plus keys; duplicate slash/dot-segment keys; duplicate and empty subresource values; and auth-query exclusion.

### Phase 6: S3 SigV2 Signed URLs

Add `src\AWSSignatureGenerator\V2SignedUrlResult.cs`.

Constructor and validation:

- [x] Validate `httpMethod`, `fullUrl`, `accessKey`, and `secretKey`.
- [x] Validate `expires` is greater than zero.
- [x] Accept `DateTimeOffset expiresAt` and convert to Unix epoch seconds.
- [x] Reject existing `Signature` query parameter by default to avoid double-signing ambiguity.
- [x] Reject or overwrite existing `AWSAccessKeyId` and `Expires` deterministically. Preferred behavior: reject with clear exception.
- [x] Accept optional headers so `Content-MD5`, `Content-Type`, and `x-amz-*` headers can be part of the signed URL.
- [x] Document that any signed headers must be supplied by the eventual URL consumer.

Core fields:

- [x] `Expires`: Unix epoch seconds.
- [x] `ExpiresAt`: `DateTimeOffset`.
- [x] `ContentMd5`: value from headers or empty.
- [x] `ContentType`: value from headers or empty.
- [x] `CanonicalizedAmzHeaders`: same rules as header signing.
- [x] `CanonicalizedResource`: same rules as header signing, excluding auth query params.
- [x] `StringToSign`: same as header signing except `DateElement` is replaced with `Expires`.
- [x] `Signature`: Base64 HMAC-SHA1.
- [x] `EncodedSignature`: RFC 3986 encoded `Signature`.
- [x] `SignedUrl`: original URL plus `AWSAccessKeyId`, `Expires`, and encoded `Signature`.

String-to-sign:

```text
HTTP-Verb + "\n" +
Content-MD5 + "\n" +
Content-Type + "\n" +
Expires + "\n" +
CanonicalizedAmzHeaders +
CanonicalizedResource
```

Query construction:

- [x] Preserve existing non-auth query parameters and their order in the output URL unless there is a strong reason to sort output.
- [x] Append `AWSAccessKeyId`, `Expires`, and `Signature`.
- [x] Encode auth parameter values once.
- [x] Ensure `+`, `/`, and `=` in Base64 signatures become `%2B`, `%2F`, and `%3D`.
- [x] Use uppercase percent-encoding.

Progress notes:

- Hardening pass added tests for no-slash subresource URLs, encoded response overrides, preserved `x-amz-security-token` query parameters, retained non-auth queries during validation, and long-lived expiration values.

### Phase 7: Optional AWS Query API SigV2

Only implement this phase if the initial S3 work is stable and the release owner explicitly wants non-S3 support.

- [ ] Add `V2QuerySignatureResult`, not a mode on the S3 classes.
- [ ] Support `SignatureVersion=2`.
- [ ] Support `SignatureMethod=HmacSHA256` first.
- [ ] Consider `HmacSHA1` only if needed for a documented service.
- [ ] Support either `Timestamp` or `Expires`, but not both.
- [ ] Canonicalize query/body form parameters using RFC 3986.
- [ ] Sign:

```text
HTTPVerb + "\n" +
lowercase-host + "\n" +
path + "\n" +
canonicalized-query-string
```

- [ ] Return `Signature` as Base64 and `SignedUrl` or signed parameters with URL-encoded signature.
- [ ] Add SimpleDB official example tests.
- [ ] Keep docs explicit that this is AWS Query SigV2, not S3 SigV2.

Progress notes:

- Notes:

## Test Plan

Target: 100% meaningful coverage of new V2 behavior. Every public property, branch, canonicalization rule, and error path should have a test. Existing V4 tests must continue to pass.

Migrate the test infrastructure to Touchstone NuGet packages before expanding V2 coverage. The local Touchstone source can be consulted during implementation, but this repository must consume Touchstone only through NuGet package references. Do not add project references to `C:\Code\Touchstone`.

Target test architecture:

- `Test.Shared` is the source of truth for all test definitions.
- `Test.Shared` uses Touchstone core descriptors and contains all assertions, fixtures, helpers, and shared suites.
- `Test.Automated` is only a console runner using the Touchstone CLI package.
- `Test.Xunit` is only an xUnit runner using the Touchstone xUnit adapter package.
- `Test.Nunit` is only an NUnit runner using the Touchstone NUnit adapter package.
- No runner project contains AWS signature test logic beyond binding shared Touchstone suites to that runner.

### Touchstone Migration

Projects and packages:

- [x] Update `src\Test.Shared\Test.Shared.csproj` to reference the Touchstone core NuGet package, currently expected package ID: `Touchstone.Core`.
- [x] Keep `Test.Shared` referencing `AWSSignatureGenerator`.
- [x] Update `src\Test.Automated\Test.Automated.csproj` to reference the Touchstone CLI NuGet package, currently expected package ID: `Touchstone.Cli`.
- [x] Keep `Test.Automated` referencing only `Test.Shared` plus runner packages.
- [x] Update `src\Test.Xunit\Test.Xunit.csproj` to reference the Touchstone xUnit adapter NuGet package, currently expected package ID: `Touchstone.XunitAdapter`.
- [x] Keep `Test.Xunit` references to `Microsoft.NET.Test.Sdk`, `xunit`, and `xunit.runner.visualstudio`.
- [x] Keep `Test.Xunit` referencing only `Test.Shared` plus runner packages.
- [x] Add `src\Test.Nunit\Test.Nunit.csproj`.
- [x] Add `Test.Nunit` to `src\AWSSignatureGenerator.sln`.
- [x] Add NuGet package references to `Test.Nunit` for:
  - `Touchstone.NunitAdapter`
  - `Microsoft.NET.Test.Sdk`
  - `NUnit`
  - `NUnit3TestAdapter`
  - `NUnit.Analyzers`
- [x] Keep `Test.Nunit` referencing only `Test.Shared` plus runner packages.
- [x] Pin explicit Touchstone package versions rather than using floating versions.
- [x] Confirm package restore works from configured NuGet feeds without any local Touchstone source project references.

Shared test source:

- [x] Replace or retire the current custom `TestCase` and `TestResult` types in `Test.Shared` in favor of Touchstone descriptor classes.
- [x] Add a shared suite catalog, for example `AwsSignatureSuites`, exposing `IReadOnlyList<TestSuiteDescriptor> All`.
- [x] Keep V4 test definitions in shared suites, for example `V4SignatureSuites`.
- [x] Add V2 test definitions in shared suites, for example `V2SignatureSuites`.
- [x] Ensure `AwsSignatureSuites.All` includes both V4 and V2 suites.
- [x] Keep assertion helpers in `Test.Shared`, runner-agnostic, throwing exceptions on failure.
- [x] Keep golden fixtures and parser helpers in `Test.Shared`.
- [x] Keep all skip decisions, tags, fixture data, and test IDs in `Test.Shared`.

Runner projects:

- [x] Update `Test.Automated` so `Program.cs` calls the Touchstone console runner against `AwsSignatureSuites.All`.
- [x] Preserve or add CLI support for optional result output if supported by the Touchstone CLI runner.
- [x] Update `Test.Xunit` so it exposes shared descriptors through the Touchstone xUnit adapter.
- [x] Add `Test.Nunit` so it exposes shared descriptors through the Touchstone NUnit adapter.
- [x] Ensure xUnit and NUnit runners report each non-skipped Touchstone test case as an individual test case, not one aggregate test when adapter support allows it.
- [x] Ensure skipped Touchstone cases are represented consistently in all three runners.

Migration verification:

- [x] Run `dotnet restore src\AWSSignatureGenerator.sln`.
- [x] Run `dotnet build src\AWSSignatureGenerator.sln`.
- [x] Run `dotnet run --project src\Test.Automated\Test.Automated.csproj`.
- [x] Run `dotnet test src\Test.Xunit\Test.Xunit.csproj`.
- [x] Run `dotnet test src\Test.Nunit\Test.Nunit.csproj`.
- [x] Run `dotnet test src\AWSSignatureGenerator.sln`.
- [x] Confirm the same shared V4 and V2 test case count is visible through `Test.Automated`, `Test.Xunit`, and `Test.Nunit`, accounting only for runner-specific skip reporting differences.
- [x] Confirm no test runner references `AWSSignatureGenerator` directly except transitively through `Test.Shared`.
- [x] Confirm no project references the Touchstone source tree.

### Test Categories

Signature authenticity and parsing:

- [x] Do not use placeholder signatures such as `placeholder`, `abcdef`, `signature`, or hard-coded non-HMAC values in V2 tests.
- [x] Every positive V2 signature fixture must contain a real Base64 HMAC output generated from a known access key, secret key, request fields, and exact `StringToSign`.
- [x] Every positive `AuthorizationHeader` fixture must be parseable as `AWS {AWSAccessKeyId}:{Signature}`.
- [x] Parsed header signatures must be validated with `Convert.FromBase64String` and must decode to the expected HMAC byte length for the selected algorithm.
- [x] Parsed header access keys must match the fixture access key.
- [x] Every positive signed URL fixture must contain parseable `AWSAccessKeyId`, `Expires`, and `Signature` query parameters.
- [x] Signed URL `Signature` values must be URL-decoded exactly once, parsed as Base64, and compared to the recomputed `V2SignedUrlResult.Signature`.
- [x] Tests must include at least one header-auth fixture whose `AuthorizationHeader` is supplied as an incoming raw header, parsed, and validated by recomputing the signature.
- [x] Tests must include at least one signed URL fixture supplied as an incoming raw URL, parsed, and validated by recomputing the signature from the request fields.
- [x] Negative tests must include malformed V2 headers and URLs that fail parsing before signature comparison.
- [x] Negative tests must include parseable but incorrect Base64 signatures that parse successfully and then fail recomputation comparison.
- [ ] If AWS Query API SigV2 is included, its signatures must also use actual Base64 HMAC outputs and parseable query parameters, not placeholders. Deferred because AWS Query API SigV2 is out of scope for this S3-focused release.

Constructor validation:

- [x] Null `httpMethod` throws.
- [x] Empty `httpMethod` throws.
- [x] Null `fullUrl` throws.
- [x] Empty `fullUrl` throws.
- [x] Relative URL throws.
- [x] Null `accessKey` throws.
- [x] Empty `accessKey` throws.
- [x] Null `secretKey` throws.
- [x] Empty `secretKey` throws.
- [x] Header signing with neither `Date` nor `x-amz-date` throws.
- [x] Signed URL with `expires <= 0` throws.
- [x] Signed URL with existing `Signature` query parameter throws.
- [x] Signed URL with existing `AWSAccessKeyId` query parameter throws or follows documented overwrite behavior.
- [x] Signed URL with existing `Expires` query parameter throws or follows documented overwrite behavior.

Basic header signing:

- [x] GET object with `Date` only.
- [x] PUT object with `Content-Type`.
- [x] PUT object with `Content-MD5`.
- [x] PUT object with both `Content-MD5` and `Content-Type`.
- [x] DELETE object.
- [x] HEAD object.
- [x] Empty content headers produce empty string-to-sign lines.
- [x] `AuthorizationHeader` equals `AWS {AccessKey}:{Signature}`.
- [x] `Signature` is Base64, not hex.
- [x] `Signature` can be decoded with `Convert.FromBase64String`.
- [x] `AuthorizationHeader` can be parsed back into access key and signature fields.
- [x] `StringToSign` uses `\n` only.

Date and `x-amz-date` behavior:

- [x] `Date` header signs as the date element when no `x-amz-date` exists.
- [x] `x-amz-date` causes the date element to be empty.
- [x] `x-amz-date` appears in `CanonicalizedAmzHeaders`.
- [x] Header names are case-insensitive.
- [x] Multiple `x-amz-date` casing variants are handled deterministically.

CanonicalizedAmzHeaders:

- [x] No `x-amz-*` headers returns empty string.
- [x] Single `x-amz-meta-*` header signs correctly.
- [x] Multiple `x-amz-*` headers sort by lowercase name.
- [x] Header names are lowercased.
- [x] Values are trimmed.
- [x] Repeated internal spaces are handled per spec.
- [x] Folded whitespace is normalized.
- [x] Duplicate header names combine correctly.
- [x] Duplicate values match AWS example behavior.
- [x] `x-amz-security-token` signs correctly.
- [x] Non-`x-amz-*` custom headers are excluded.

CanonicalizedResource, addressing:

- [x] Path-style object URL.
- [x] Path-style bucket root URL.
- [x] Path-style service root URL.
- [x] Virtual-hosted-style object URL.
- [x] Virtual-hosted-style bucket root URL.
- [x] Virtual-hosted-style key with nested folders.
- [x] Virtual-hosted-style key with spaces or `%20`.
- [x] Key with plus sign.
- [x] Key with duplicate slashes.
- [x] Key with already encoded UTF-8.
- [x] Custom endpoint with explicit bucket.
- [x] Custom endpoint without explicit bucket signs path only.
- [x] CNAME endpoint with explicit bucket.
- [x] Explicit bucket is not duplicated when URL is already path-style.

CanonicalizedResource, subresources:

- [x] `?acl`
- [x] `?location`
- [x] `?uploads`
- [x] `?uploadId=value`
- [x] `?partNumber=value&uploadId=value`
- [x] `?versionId=value`
- [x] Multiple subresources sort correctly.
- [x] Non-subresource query parameters are excluded.
- [x] Mixed subresource and non-subresource query parameters include only subresources.
- [x] Response override parameters are included.
- [x] Empty subresource values are formatted correctly.
- [x] Auth query parameters are excluded from canonical resource.

Signed URLs:

- [x] GET signed URL includes `AWSAccessKeyId`, `Expires`, and `Signature`.
- [x] PUT signed URL includes correct signature when `Content-Type` is signed.
- [x] Existing query parameters are preserved in `SignedUrl`.
- [x] Existing subresources affect the signature.
- [x] Existing non-subresource parameters do not affect `CanonicalizedResource`.
- [x] Signature is URL encoded exactly once.
- [x] URL-decoded `Signature` can be parsed with `Convert.FromBase64String`.
- [x] `AWSAccessKeyId`, `Expires`, and `Signature` can be parsed back from the generated `SignedUrl`.
- [x] Base64 `+`, `/`, and `=` are encoded.
- [x] `DateTimeOffset` constructor produces same result as epoch seconds.
- [x] Signed URL with `x-amz-*` headers documents and signs required headers.
- [x] Temporary security token query behavior is covered after verification.
- [x] Long-lived expiration values work for legacy SigV2 use cases.

Official and cross-implementation vectors:

- [x] Add high-confidence AWS S3 SigV2 header-auth examples as golden tests, including GET, PUT, list-bucket, and CNAME metadata cases.
- [ ] Add every still-published AWS S3 SigV2 query-auth example as a golden test. No current official query-auth golden signature was added; generated signed URL vectors cover parseability and recomputation.
- [x] Add independently generated HMAC fixtures outside the library implementation.
- [x] Golden tests must assert the expected `StringToSign`, raw Base64 `Signature`, parseable `AuthorizationHeader` or `SignedUrl`, and recomputed validation result.
- [ ] If AWS Query API support is included, add the SimpleDB SigV2 example as a golden test. Deferred with AWS Query API SigV2.

Server-side validation:

- [x] Given a received header-auth request, recomputing `V2SignatureResult.Signature` matches the parsed `Authorization` signature.
- [x] Given a received signed URL, recomputing `V2SignedUrlResult.Signature` matches the decoded query `Signature`.
- [x] Header validation tests parse the access key and signature from the raw `Authorization` header before comparing.
- [x] Signed URL validation tests parse the access key, expiration, and signature from the raw URL before comparing.
- [x] A changed path changes the signature.
- [x] A changed date or expiration changes the signature.
- [x] A changed signed `x-amz-*` header changes the signature.
- [x] A changed unsigned ordinary header does not change the signature.
- [x] A changed HTTP method changes the signature.
- [x] A changed signed URL subresource changes the signature.
- [x] Wrong access key is detected before signature comparison.

Regression protection:

- [x] Run all existing V4 tests unchanged.
- [x] Add a test that references both V2 and V4 result types in the same project to catch namespace/API conflicts.
- [x] Confirm adding V2 does not alter generated XML docs for V4 public members except timestamp/order churn if unavoidable.

Coverage and quality:

- [ ] Add coverage tooling if not already present. Deferred; meaningful branch and public API coverage was expanded through shared Touchstone tests.
- [x] Target 100% meaningful behavior and branch coverage for new V2 classes through shared Touchstone tests.
- [x] Any known uncovered branch must be listed in this document with a reason.
- [x] All tests pass for every target framework supported by the project.
- [x] No test depends on live AWS by default.
- [ ] Environment-gated live/S3-compatible tests are skipped when credentials or endpoint variables are absent. Deferred; no live integration test project exists in this release.

Suggested optional integration environment variables:

```text
AWSSG_V2_S3_ENDPOINT
AWSSG_V2_S3_ACCESS_KEY
AWSSG_V2_S3_SECRET_KEY
AWSSG_V2_S3_BUCKET
AWSSG_V2_S3_REGION
AWSSG_V2_S3_FORCE_PATH_STYLE
```

## Documentation Plan

README:

- [x] Update the first paragraph to say the library supports AWS V4 and legacy S3 V2 signatures.
- [x] Add a warning that SigV2 is deprecated for AWS S3 and should only be used for legacy or S3-compatible requirements.
- [x] Add "Standard V2 Signatures" section with `V2SignatureResult` example.
- [x] Add "V2 Signed URLs" section with `V2SignedUrlResult` example.
- [x] Add a short comparison table:
  - V4: current AWS default, region/service scoped, SHA-256, streaming support.
  - S3 V2: legacy S3 auth, Base64 HMAC-SHA1, date/expiration based, no streaming chunk signatures.
- [x] Add API reference entries for `V2SignatureResult` and `V2SignedUrlResult`.
- [x] Mention that S3 SigV2 and AWS Query API SigV2 are different if Query API support is added or deferred.
- [x] Keep all existing V4 examples intact.

XML docs:

- [x] Add XML comments for every new public type, constructor, property, and method.
- [x] Ensure generated `AWSSignatureGenerator.xml` includes new V2 members.
- [x] Do not manually edit generated XML if the build regenerates it.

Package metadata:

- [x] Update `.csproj` description from V4-only to V4 plus legacy S3 V2 if the feature ships.
- [x] Update package tags to include `v2`, `s3`, `presigned`, and `legacy`.
- [x] Keep existing V4 tags.

Changelog:

- [x] Add a version entry.
- [x] State that V2 support is additive.
- [x] State that V4 behavior is unchanged.
- [x] State whether AWS Query API SigV2 is included or deferred.

Examples:

- [x] Add sample output for V2 header signing.
- [x] Add sample output for V2 signed URL generation.

## Compatibility and Risk Register

| Risk | Impact | Mitigation | Status |
| --- | --- | --- | --- |
| S3 SigV2 is deprecated on AWS | Users may expect modern AWS S3 support where it no longer works | Document legacy status prominently; keep V4 as primary recommendation | [x] |
| S3 SigV2 and AWS Query SigV2 differ | Incorrect generic V2 behavior | Separate public types and docs | [x] |
| CanonicalizedResource rules are subtle | Signature mismatches | Golden vectors, subresource matrix, explicit bucket override | [x] |
| URL encoding differences | Signature mismatches | RFC 3986 helper tests, encoded path/query fixtures | [x] |
| `NameValueCollection` duplicate behavior | Header canonicalization bugs | Explicit duplicate-header tests | [x] |
| Test definitions drift between runners | Different runner results | Use `Test.Shared` Touchstone suites as the only source of truth | [x] |
| Accidental Touchstone source references | Non-reproducible builds outside the developer machine | Use NuGet package references only; verify no `C:\Code\Touchstone` project references | [x] |
| Code style drift during migration | Harder reviews and inconsistent project shape | Apply `C:\Code\Agents\requirements\CODE_STYLE.md`; review for no `var`, no tuples, namespace/using order, and one type per file | [x] |
| Shared tests gaining runner logic | Duplicated or inconsistent test behavior | Keep all assertions in `Test.Shared`; keep xUnit, NUnit, and console projects as adapters only | [x] |
| Refactoring shared helpers could affect V4 | Regression in existing users | Avoid V4 changes in initial implementation unless necessary | [x] |
| Temporary credentials in signed URLs are easy to mishandle | Broken STS workflows | Preserve and parse `x-amz-security-token` query parameters; document no automatic token injection API in this release | [x] |
| Third-party S3-compatible systems vary | Support burden | Document AWS-compatible behavior; add env-gated endpoint tests | [ ] |

## Acceptance Criteria

Library:

- [ ] `V2SignatureResult` signs S3 REST header requests using SigV2.
- [ ] `V2SignedUrlResult` creates S3 SigV2 signed URLs.
- [ ] Public shape is consistent with V4 result-object usage.
- [ ] No V4 public API changes.
- [ ] No V4 behavior changes.
- [ ] New API is documented with XML comments.
- [ ] New and materially changed library code follows `C:\Code\Agents\requirements\CODE_STYLE.md`.
- [ ] New and materially changed library code contains no `var` declarations.
- [ ] New and materially changed library code contains no tuples or `ValueTuple` usage.
- [ ] New public APIs document expected exceptions with XML `<exception>` tags where applicable.
- [ ] New library files contain exactly one public class or enum per file.

Tests:

- [x] Test infrastructure is migrated to Touchstone NuGet packages.
- [x] `Test.Shared` is the only source of test definitions, fixtures, assertions, and test descriptors.
- [x] `Test.Automated`, `Test.Xunit`, and `Test.Nunit` are runner-only projects.
- [x] `Test.Nunit` exists and is included in `src\AWSSignatureGenerator.sln`.
- [x] No project references the Touchstone source tree.
- [x] Test projects follow `C:\Code\Agents\requirements\BACKEND_TEST_ARCHITECTURE.md`.
- [x] New and materially changed test code contains no `var` declarations.
- [x] New and materially changed test code contains no tuples or `ValueTuple` usage.
- [x] `Test.Shared` contains no console output and no runner-specific framework attributes.
- [x] Existing V4 tests pass.
- [x] New V2 tests cover constructor validation.
- [x] New V2 tests cover all canonical string fields.
- [x] New V2 tests cover header signing.
- [x] New V2 tests cover signed URLs.
- [x] New V2 tests validate actual parseable Base64 HMAC signatures, not placeholder values.
- [x] New V2 tests parse and validate raw incoming `Authorization` headers and signed URLs.
- [x] New V2 tests cover path-style, virtual-hosted-style, and explicit-bucket custom endpoints.
- [x] New V2 tests cover all subresources and response override parameters listed in code.
- [x] New V2 code has 100% meaningful behavior and branch coverage, or documented exceptions.
- [x] No live AWS dependency in default test runs.
- [x] `dotnet run --project src\Test.Automated\Test.Automated.csproj` passes.
- [x] `dotnet test src\Test.Xunit\Test.Xunit.csproj` passes.
- [x] `dotnet test src\Test.Nunit\Test.Nunit.csproj` passes.
- [x] `dotnet test src\AWSSignatureGenerator.sln` passes.

Documentation:

- [x] README reflects V2 as legacy support.
- [x] README includes V2 header-signing example.
- [x] README includes V2 signed URL example.
- [x] Documentation touched by the work follows `C:\Code\Agents\requirements\WRITING_DOCUMENTS.md` where applicable.
- [x] API reference includes V2 types.
- [x] Changelog includes the release.
- [x] Package metadata no longer says V4-only after the feature ships.

Release:

- [x] Version chosen: next minor version, currently planned as `1.1.0`.
- [x] All Touchstone-backed automated, xUnit, NUnit, and solution-level tests pass before release build.
- [x] Style review confirms no `var`, no tuples, no runner logic in `Test.Shared`, and no Touchstone source references.
- [x] Release build succeeds with `dotnet build src\AWSSignatureGenerator.sln -c Release`.
- [x] NuGet package builds after the release build succeeds.
- [x] Release notes state the feature is additive.
- [x] Release notes state SigV2 is deprecated for AWS S3 and V4 remains preferred.

## Suggested Implementation Order

1. Migrate test infrastructure to Touchstone NuGet packages.
2. Add `Test.Nunit` and wire all three runners to `Test.Shared` suites.
3. Convert existing V4 tests into Touchstone descriptors and confirm all runners pass.
4. Add `V2SignatureResult` with header signing and a small initial Touchstone test set.
5. Finish canonicalized `x-amz-*` headers and canonicalized resource coverage.
6. Add `V2SignedUrlResult`.
7. Fill out the full V2 test matrix in `Test.Shared`.
8. Add docs and metadata updates.
9. Consider optional AWS Query API SigV2 only after S3 coverage is complete.
10. Run final regression, release build, and package validation.

Progress:

- [x] Implementation complete.
- [x] Touchstone migration completed.
- [x] `Test.Nunit` added.
- [x] Existing V4 tests converted to Touchstone descriptors.
- [x] Header signing implemented.
- [x] Header signing tested.
- [x] Signed URLs implemented.
- [x] Signed URLs tested.
- [x] Official AWS header-auth vectors added.
- [x] Descriptor display names identify V2 vs V4 at the runner row level.
- [x] V2 case descriptors use category-specific suite IDs.
- [x] CanonicalizedAmzHeaders hardened for duplicate value order, whitespace, empty values, and case-insensitive dates.
- [x] CanonicalizedResource hardened for regional hosts, no-slash query URLs, encoded keys, plus signs, duplicate slashes, dot segments, empty duplicate subresources, and auth-query exclusion.
- [x] V2 public API surface tests added.
- [x] Documentation updated.
- [x] Package metadata updated.
- [x] Release-ready.

Final verification:

- `dotnet test src\Test.Xunit\Test.Xunit.csproj --framework net8.0`: 160 passed, 0 failed.
- `dotnet run --project src\Test.Automated\Test.Automated.csproj --framework net8.0`: 160 passed, 0 failed.
- `dotnet test src\AWSSignatureGenerator.sln`: xUnit and NUnit each passed 160 tests on net8.0 and net10.0.
- `dotnet test src\AWSSignatureGenerator.sln -c Release`: xUnit and NUnit each passed 160 tests on net8.0 and net10.0.
- `dotnet build src\AWSSignatureGenerator.sln -c Release`: succeeded with 0 warnings and 0 errors.
- Release package artifacts: `AWSSignatureGenerator.1.1.0.nupkg` and `AWSSignatureGenerator.1.1.0.snupkg`.
