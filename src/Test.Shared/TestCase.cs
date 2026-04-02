namespace Test.Shared
{
    using System;

    /// <summary>
    /// Represents a single test case with a name, description, and action to execute.
    /// </summary>
    public class TestCase
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
        /// Action to execute for this test case.
        /// </summary>
        public Action TestAction
        {
            get
            {
                return _TestAction;
            }
            set
            {
                _TestAction = value ?? throw new ArgumentNullException(nameof(TestAction));
            }
        }

        private string _Name = null;
        private string _Description = null;
        private Action _TestAction = null;
    }
}
