namespace Test.Shared
{
    using System;

    /// <summary>
    /// Result of executing a single test case.
    /// </summary>
    public class TestResult
    {
        /// <summary>
        /// Test case name.
        /// </summary>
        public string Name
        {
            get
            {
                return _Name;
            }
            set
            {
                if (String.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(Name));
                _Name = value;
            }
        }

        /// <summary>
        /// Test case description.
        /// </summary>
        public string Description
        {
            get
            {
                return _Description;
            }
            set
            {
                if (String.IsNullOrEmpty(value)) throw new ArgumentNullException(nameof(Description));
                _Description = value;
            }
        }

        /// <summary>
        /// Whether the test passed.
        /// </summary>
        public bool Passed { get; set; } = false;

        /// <summary>
        /// Duration of the test execution.
        /// </summary>
        public TimeSpan Duration { get; set; } = TimeSpan.Zero;

        /// <summary>
        /// Error message if the test failed, or null if it passed.
        /// </summary>
        public string ErrorMessage { get; set; } = null;

        private string _Name = null;
        private string _Description = null;
    }
}
