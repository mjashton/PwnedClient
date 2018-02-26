namespace PwnedClient
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security.Cryptography;
    using System.Text;

    public class PwnedClient
    {
        private HttpClient client = new HttpClient();
        private Uri baseUri = new Uri("https://api.pwnedpasswords.com/range/");

        public PwnedClient()
        {
            this.client.BaseAddress = this.baseUri;
            this.client.DefaultRequestHeaders.Add("api-version","2");
            this.client.DefaultRequestHeaders.Add("User-Agent", "PwnedClient.Net");
        }

        public bool IsCompromisedPlainTextPassword(string password)
        {
            var hashedPassword = password.ToSha1Hash();
            return this.IsCompromisedHashedPassword(hashedPassword);
        }

        public bool IsCompromisedHashedPassword(string hashedPassword)
        {
            var suffix = hashedPassword.GetSuffix();

            var results = this.GetSearchResults(hashedPassword.FirstFive());
            return results.Contains(suffix);
        }

        public Dictionary<string,int> GetMatchesForPartialHash(string hashedPassword)
        {
            var results = this.GetRawMatchesForPartialHash(hashedPassword);
            return ResultsAsDictionary(results);
        }

        public string GetRawMatchesForPartialHash(string hashedPassword)
        {
            return this.GetSearchResults(hashedPassword.FirstFive());
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



        private string GetSearchResults(string searchUri)
        {
            var response = this.client.GetAsync(searchUri).Result;
            var results = response.Content.ReadAsStringAsync().Result;
            return results;
        }
    }

    public static class StringExtensions
    {
        public static string ToSha1Hash(this string input)
        {
            using (var sha1 = new SHA1Managed())
            {
                var hash = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                var sb = new StringBuilder(hash.Length * 2);

                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("X2"));
                }

                return sb.ToString();
            }
        }

        public static string GetSuffix(this string input)
        {
            return input.Substring(5, input.Length - 5);
        }

        public static string FirstFive(this string input)
        {
            return input.Substring(0, 5);
        }

        public static IEnumerable<string> SplitToLines(this string input)
        {
            if (input == null)
            {
                yield break;
            }

            using (StringReader reader = new StringReader(input))
            {
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    yield return line;
                }
            }
        }
    }
}