namespace PwnedClient.Tests
{
    using FluentAssertions;
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class WhenTestingPartialHash
    {
        private PwnedClient passwordChecker;

        [TestInitialize]
        public void Setup()
        {
            this.passwordChecker = new PwnedClient();
        }

        [TestMethod]
        public void BreachedPassword_IsInRange()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetMatchesForPartialHash(firstFive);
            result.Should().ContainKey(suffix);
        }

        [TestMethod]
        public void RandomPassword_IsNotInRange()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetMatchesForPartialHash(firstFive);
            result.Should().NotContainKey(suffix);
        }

        [TestMethod]
        public void CompleteBreachedPassword_IsInRange()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetMatchesForPartialHash(hashedPassword);
            result.Should().ContainKey(suffix);
        }
    }
}
