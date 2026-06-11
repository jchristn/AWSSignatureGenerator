namespace Test.Nunit
{
    using System.Collections;
    using System.Threading;
    using System.Threading.Tasks;

    using NUnit.Framework;

    using Test.Shared;
    using Touchstone.Core;
    using Touchstone.NunitAdapter;

    /// <summary>
    /// NUnit runner for shared AWSSignatureGenerator Touchstone test descriptors.
    /// </summary>
    [TestFixture]
    public sealed class AwsSignatureNunitTests
    {
        /// <summary>
        /// Provides all shared test cases as NUnit test case source data.
        /// </summary>
        /// <returns>Enumerable of shared test descriptors.</returns>
        public static IEnumerable TestCases()
        {
            return new TouchstoneTestCaseSource(AwsSignatureSuites.All);
        }

        /// <summary>
        /// Executes a single shared test case.
        /// </summary>
        /// <param name="testCase">Test case descriptor.</param>
        [Test]
        [TestCaseSource(nameof(TestCases))]
        public async Task RunTest(TestCaseDescriptor testCase)
        {
            await testCase.ExecuteAsync(CancellationToken.None);
        }
    }
}
