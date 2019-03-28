using System.Threading.Tasks;

namespace PwnedClient.Tests
{
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using FluentAssertions;


    [TestClass]
    public class WhenTestingPlainTextPasswordsAsync
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
            var result = await this.passwordChecker.IsCompromisedAsync(password);
            result.Should().BeTrue();
        }

        [TestMethod]
        public async Task BreachedPassword_ReturnsTrue()
        {
            var password = "password123";
            var result = await this.passwordChecker.IsCompromisedPlainTextPasswordAsync(password);
            result.Should().BeTrue();
        }

        [TestMethod]
        public async Task RandomPassword_ReturnsFalse()
        {
            var password = Guid.NewGuid().ToString();
            var result = await this.passwordChecker.IsCompromisedPlainTextPasswordAsync(password);
            result.Should().BeFalse();
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Func<Task> act = async () => await this.passwordChecker.IsCompromisedPlainTextPasswordAsync(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            Func<Task> act = async () => await this.passwordChecker.IsCompromisedPlainTextPasswordAsync(null);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public async Task BreachedPassword_ReturnsPositiveBreachCount()
        {
            var password = "password123";
            var count = await this.passwordChecker.GetBreachCountAsync(password);
            count.Should().BePositive();
        }

        [TestMethod]
        public async Task RandomPassword_ReturnsZeroBreachCount()
        {
            var password = Guid.NewGuid().ToString();
            var count = await this.passwordChecker.GetBreachCountAsync(password);
            count.Should().Be(0);
        }
    }
}
