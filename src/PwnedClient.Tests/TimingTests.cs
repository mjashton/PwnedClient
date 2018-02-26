using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PwnedClient.Tests
{
    using System.Collections.Generic;
    using System.Linq;

    [TestClass]
    public class TimingTests
    {
        private PwnedClient passwordChecker;

        [TestInitialize]
        public void Setup()
        {
            this.passwordChecker = new PwnedClient();
        }

        [TestMethod]
        public void TimeRawContains()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetRawMatchesForPartialHash(firstFive);

            var watch = System.Diagnostics.Stopwatch.StartNew();

            var t = result.Contains(suffix);

            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
        }

        [TestMethod]
        public void TimeDictionaryCheck()
        {
            var password = "password123";
            var hashedPassword = password.ToSha1Hash();
            var firstFive = hashedPassword.Substring(0, 5);
            var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
            var result = this.passwordChecker.GetRawMatchesForPartialHash(firstFive);

            var watch = System.Diagnostics.Stopwatch.StartNew();

            var t = result.Contains(suffix);

            watch.Stop();
            var elapsedMs = watch.ElapsedMilliseconds;
        }

        private Dictionary<string, int> ResultsAsDictionary(string results)
        {
            var lines = results.SplitToLines().ToList();
            var dictionary = new Dictionary<string, int>();
            foreach (var line in lines)
            {
                var split = line.Split(':');
                dictionary.Add(split[0], Convert.ToInt32(split[1]));
            }

            return dictionary;
        }
    }
}
