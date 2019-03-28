using System.Threading.Tasks;

namespace PwnedClient.Tests
{
    using FluentAssertions;
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class WhenGettingMatchesDictionaryAsync
    {
        private PwnedClient passwordChecker;

        [TestInitialize]
        public void Setup()
        {
            this.passwordChecker = new PwnedClient();
        }

        [TestMethod]
        public async Task BreachedPassword_IsInRange()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = await this.passwordChecker.GetMatchesDictionaryAsync(firstFive);
            result.Should().ContainKey(suffix);
        }

        [TestMethod]
        public async Task RandomPassword_IsNotInRange()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = await this.passwordChecker.GetMatchesDictionaryAsync(firstFive);
            result.Should().NotContainKey(suffix);
        }

        [TestMethod]
        public async Task CompleteBreachedPassword_IsInRange()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = await this.passwordChecker.GetMatchesDictionaryAsync(hashedPassword);
            result.Should().ContainKey(suffix);
        }

        [TestMethod]
        public async Task CompleteRandomPassword_IsNotInRange()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = await this.passwordChecker.GetMatchesDictionaryAsync(hashedPassword);
            result.Should().NotContainKey(suffix);
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Func<Task> act = async () => await this.passwordChecker.GetMatchesDictionaryAsync(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            Func<Task> act = async () => await this.passwordChecker.GetMatchesDictionaryAsync(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }
    }
}
