namespace Test.Automated
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using Test.Shared;

    /// <summary>
    /// Console-based test runner for AWSSignatureGenerator.
    /// </summary>
    public static class Program
    {
        /// <summary>
        /// Entry point.
        /// </summary>
        /// <param name="args">Command-line arguments.</param>
        /// <returns>0 if all tests pass, 1 if any fail.</returns>
        public static int Main(string[] args)
        {
            List<TestCase> tests = V4SignatureTests.GetAllTests();
            List<TestResult> results = new List<TestResult>();
            Stopwatch totalSw = Stopwatch.StartNew();

            Console.WriteLine();
            Console.WriteLine("AWSSignatureGenerator Test Suite");
            Console.WriteLine("================================");
            Console.WriteLine();

            int passed = 0;
            int failed = 0;

            foreach (TestCase test in tests)
            {
                Stopwatch sw = Stopwatch.StartNew();
                TestResult result = new TestResult
                {
                    Name = test.Name,
                    Description = test.Description
                };

                try
                {
                    test.TestAction();
                    sw.Stop();
                    result.Passed = true;
                    result.Duration = sw.Elapsed;
                    passed++;
                    Console.WriteLine($"  PASS  {test.Name} ({sw.Elapsed.TotalMilliseconds:F1}ms)");
                    Console.WriteLine($"        {test.Description}");
                }
                catch (Exception ex)
                {
                    sw.Stop();
                    result.Passed = false;
                    result.Duration = sw.Elapsed;
                    result.ErrorMessage = ex.Message;
                    failed++;
                    Console.WriteLine($"  FAIL  {test.Name} ({sw.Elapsed.TotalMilliseconds:F1}ms)");
                    Console.WriteLine($"        {test.Description}");
                    Console.WriteLine($"        Error: {ex.Message}");
                }

                results.Add(result);
            }

            totalSw.Stop();

            Console.WriteLine();
            Console.WriteLine("================================");
            Console.WriteLine($"Total: {results.Count} | Passed: {passed} | Failed: {failed} | Runtime: {totalSw.Elapsed.TotalMilliseconds:F1}ms");

            if (failed > 0)
            {
                Console.WriteLine();
                Console.WriteLine("Failed tests:");
                foreach (TestResult r in results)
                {
                    if (!r.Passed)
                    {
                        Console.WriteLine($"  - {r.Name}: {r.ErrorMessage}");
                    }
                }

                Console.WriteLine();
                Console.WriteLine("RESULT: FAIL");
                return 1;
            }
            else
            {
                Console.WriteLine();
                Console.WriteLine("RESULT: PASS");
                return 0;
            }
        }
    }
}
