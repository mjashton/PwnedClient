namespace PwnedClient.Tests
{
    using FluentAssertions;
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class WhenGettingMatchesRaw
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
            var result = this.passwordChecker.GetMatchesRaw(firstFive);
            result.Should().Contain(suffix);
        }

        [TestMethod]
        public void RandomPassword_IsNotInRange()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetMatchesRaw(firstFive);
            result.Should().NotContain(suffix);
        }

        [TestMethod]
        public void CompleteBreachedPassword_IsInRange()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetMatchesRaw(hashedPassword);
            result.Should().Contain(suffix);
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Action act = () => this.passwordChecker.GetMatchesRaw(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            string password = null;
            Action act = () => this.passwordChecker.GetMatchesRaw(password);
            act.Should().ThrowExactly<ArgumentNullException>();
        }
    }
}
