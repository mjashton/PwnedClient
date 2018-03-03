using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using FluentAssertions;

namespace PwnedClient.Tests
{


    [TestClass]
    public class WhenTestingHashedPasswords
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
            var result = this.passwordChecker.IsCompromised(password.ToSha1Hash(), isHashed:true);
            result.Should().BeTrue();
        }

        [TestMethod]
        public void BreachedPassword_ReturnsTrue()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var result = this.passwordChecker.IsCompromisedHashedPassword(hashedPassword);
            result.Should().BeTrue();
        }

        [TestMethod]
        public void RandomPassword_ReturnsFalse()
        {
            var password = Guid.NewGuid().ToString();
            var hashedPassword = password.ToSha1Hash();
            var result = this.passwordChecker.IsCompromisedHashedPassword(hashedPassword);
            result.Should().BeFalse();
        }

        [TestMethod]
        public void ShortPassword_ThrowsException()
        {
            var password = "1234";
            Action act = () => this.passwordChecker.IsCompromisedHashedPassword(password);
            act.Should().ThrowExactly<ArgumentException>();
        }

        [TestMethod]
        public void NullPassword_ThrowsException()
        {
            string password = null;
            Action act = () => this.passwordChecker.IsCompromisedHashedPassword(password);
            act.Should().ThrowExactly<ArgumentNullException>();
        }

        [TestMethod]
        public void BreachedPassword_ReturnsPositiveBreachCount()
        {
            var password = "password123";
            var count = this.passwordChecker.GetBreachCount(password.ToSha1Hash(),isHashed:true);
            count.Should().BePositive();
        }

        [TestMethod]
        public void RandomPassword_ReturnsZeroBreachCount()
        {
            var password = Guid.NewGuid().ToString();
            var count = this.passwordChecker.GetBreachCount(password.ToSha1Hash(),isHashed:true);
            count.Should().Be(0);
        }
    }
}
