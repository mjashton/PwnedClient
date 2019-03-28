using System;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace PwnedClient.Tests
{


    [TestClass]
    public class WhenTestingHashedPasswordsAsync
    {
        private PwnedClient passwordChecker;

        [TestInitialize]
        public void Setup()
        {
            this.passwordChecker = new PwnedClient();
        }

        [TestMethod]
        public async Task BreachedPasswordCompromised_ReturnsTrue()
        {
            var password = "password123";
            var result = await this.passwordChecker.IsCompromisedAsync(password.ToSha1Hash(), isHashed:true);
            result.Should().BeTrue();
        }

        [TestMethod]
        public async Task BreachedPassword_ReturnsTrue()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var result = await this.passwordChecker.IsCompromisedHashedPasswordAsync(hashedPassword);
            result.Should().BeTrue();
        }

        [TestMethod]
        public async Task RandomPassword_ReturnsFalse()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var result = await this.passwordChecker.IsCompromisedHashedPasswordAsync(hashedPassword);
            result.Should().BeFalse();
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Func<Task> act = async () => await this.passwordChecker.IsCompromisedHashedPasswordAsync(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            string password = null;
            Func<Task> act = async () => await this.passwordChecker.IsCompromisedHashedPasswordAsync(password);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public async Task BreachedPassword_ReturnsPositiveBreachCount()
        {
            var password = "password123";
            var count = await this.passwordChecker.GetBreachCountAsync(password.ToSha1Hash(),isHashed:true);
            count.Should().BePositive();
        }

        [TestMethod]
        public async Task RandomPassword_ReturnsZeroBreachCount()
        {
            var password = Guid.NewGuid().ToString();
            var count = await this.passwordChecker.GetBreachCountAsync(password.ToSha1Hash(),isHashed:true);
            count.Should().Be(0);
        }
    }
}
