namespace Test.Xunit
{
    using System.Collections.Generic;
    using System.Linq;
    using global::Xunit;
    using Test.Shared;

    /// <summary>
    /// xUnit wrapper for shared V4 signature test cases.
    /// </summary>
    public class V4SignatureXunitTests
    {
        /// <summary>
        /// Provides all test cases as xUnit theory data.
        /// </summary>
        /// <returns>Enumerable of test case parameters.</returns>
        public static IEnumerable<object[]> AllTestCases()
        {
            return V4SignatureTests.GetAllTests().Select(t => new object[] { t.Name, t });
        }

        /// <summary>
        /// Executes a single test case from the shared test suite.
        /// </summary>
        /// <param name="name">Test case name (used for xUnit display).</param>
        /// <param name="testCase">Test case to execute.</param>
        [Theory]
        [MemberData(nameof(AllTestCases))]
        public void RunTest(string name, TestCase testCase)
        {
            _ = name;
            testCase.TestAction();
        }
    }
}
