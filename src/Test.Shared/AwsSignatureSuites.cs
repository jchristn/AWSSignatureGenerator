namespace Test.Shared
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;

    using Touchstone.Core;

    /// <summary>
    /// Shared Touchstone suite catalog for AWSSignatureGenerator tests.
    /// </summary>
    public static class AwsSignatureSuites
    {
        /// <summary>
        /// All shared test suites.
        /// </summary>
        public static IReadOnlyList<TestSuiteDescriptor> All
        {
            get
            {
                List<TestSuiteDescriptor> suites = new List<TestSuiteDescriptor>
                {
                    V4Suite()
                };

                foreach (TestSuiteDescriptor suite in V2SignatureSuites.All)
                {
                    suites.Add(suite);
                }

                return suites;
            }
        }

        /// <summary>
        /// V4 signature compatibility suite.
        /// </summary>
        /// <returns>Touchstone suite wrapping the existing V4 test cases.</returns>
        public static TestSuiteDescriptor V4Suite()
        {
            List<TestCaseDescriptor> cases = new List<TestCaseDescriptor>();

            foreach (TestCase testCase in V4SignatureTests.GetAllTests())
            {
                TestCase capturedTestCase = testCase;

                cases.Add(new TestCaseDescriptor(
                    suiteId: "V4",
                    caseId: capturedTestCase.Name,
                    displayName: "V4 - " + capturedTestCase.Description,
                    executeAsync: cancellationToken =>
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        capturedTestCase.TestAction();
                        return Task.CompletedTask;
                    }));
            }

            return new TestSuiteDescriptor(
                suiteId: "V4",
                displayName: "AWS Signature Version 4",
                cases: cases);
        }
    }
}
