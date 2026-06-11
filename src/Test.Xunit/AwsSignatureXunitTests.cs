namespace Test.Xunit
{
    using System.Threading;
    using System.Threading.Tasks;

    using Test.Shared;
    using Touchstone.Core;
    using Touchstone.XunitAdapter;
    using global::Xunit;

    /// <summary>
    /// xUnit runner for shared AWSSignatureGenerator Touchstone test descriptors.
    /// </summary>
    public sealed class AwsSignatureXunitTests
    {
        /// <summary>
        /// Provides all shared test cases as xUnit theory data.
        /// </summary>
        /// <returns>Theory data for all shared test descriptors.</returns>
        public static TheoryData<TestCaseDescriptor> TestCases()
        {
            return new TouchstoneTheoryData(AwsSignatureSuites.All);
        }

        /// <summary>
        /// Executes a single shared test case.
        /// </summary>
        /// <param name="testCase">Test case descriptor.</param>
        [Theory]
        [MemberData(nameof(TestCases))]
        public async Task RunTest(TestCaseDescriptor testCase)
        {
            await testCase.ExecuteAsync(CancellationToken.None);
        }
    }
}
