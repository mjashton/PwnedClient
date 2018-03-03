namespace PwnedClient.Tests
{
    using System;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using FluentAssertions;


    [TestClass]
    public class WhenTestingPlainTextPasswords
    {
        private PwnedClient passwordChecker;

        [TestInitialize]
        public void Setup()
        {
            this.passwordChecker = new PwnedClient();
        }

        [TestMethod]
        public void BreachedPasswordCompromised_ReturnsTrue()
        {
            var password = "password123";
            var result = this.passwordChecker.IsCompromised(password);
            result.Should().BeTrue();
        }

        [TestMethod]
        public void BreachedPassword_ReturnsTrue()
        {
            var password = "password123";
            var result = this.passwordChecker.IsCompromisedPlainTextPassword(password);
            result.Should().BeTrue();
        }

        [TestMethod]
        public void RandomPassword_ReturnsFalse()
        {
            var password = Guid.NewGuid().ToString();
            var result = this.passwordChecker.IsCompromisedPlainTextPassword(password);
            result.Should().BeFalse();
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Action act = () => this.passwordChecker.IsCompromisedPlainTextPassword(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            string password = null;
            Action act = () => this.passwordChecker.IsCompromisedPlainTextPassword(password);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void BreachedPassword_ReturnsPositiveBreachCount()
        {
            var password = "password123";
            var count = this.passwordChecker.GetBreachCount(password);
            count.Should().BePositive();
        }

        [TestMethod]
        public void RandomPassword_ReturnsZeroBreachCount()
        {
            var password = Guid.NewGuid().ToString();
            var count = this.passwordChecker.GetBreachCount(password);
            count.Should().Be(0);
        }
    }
}
