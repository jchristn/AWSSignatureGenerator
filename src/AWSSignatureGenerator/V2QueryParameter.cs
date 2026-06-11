namespace AWSSignatureGenerator
{
    internal sealed class V2QueryParameter
    {
        internal string Name { get; set; } = null;

        internal string Value { get; set; } = null;

        internal bool HasValue { get; set; } = false;
    }
}
