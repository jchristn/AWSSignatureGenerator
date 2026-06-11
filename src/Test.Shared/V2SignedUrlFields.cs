namespace Test.Shared
{
    internal sealed class V2SignedUrlFields
    {
        internal string AccessKey { get; set; } = null;

        internal long Expires { get; set; } = 0;

        internal string Signature { get; set; } = null;

        internal string UrlWithoutSignatureParameters { get; set; } = null;
    }
}
