using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PwnedClient.Tests
{
    using FluentAssertions;
    using FluentAssertions.Execution;

    [TestClass]
    public class GuardClauseTests
    {
        [TestMethod]
        public void WhenStringTooShort_FirstFiveFails()
        {
            var test = "1234";
            Action act = () => test.FirstFive();
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void WhenStringNull_FirstFiveFails()
        {
            string test = null;
            Action act = () => test.FirstFive();
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void WhenStringTooShort_GetSuffixFails()
        {
            var test = "1234";
            Action act = () => test.GetSuffix();
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void WhenStringNull_GetSuffixFails()
        {
            string test = null;
            Action act = () => test.GetSuffix();
            act.Should().ThrowExactly<ArgumentNullException>();
        }
    }
}
