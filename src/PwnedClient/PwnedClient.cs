/*
    Provides a simple client to Troy Hunt's Pwned Passwords API
   See https://haveibeenpwned.com for full details
   This client does not send a complete password across the wire
   and uses the k-Anonymity model feature of "Have I Been Pwned?"
   to determine whether the provided password has been involved
   in a breach. Read more here ...
   https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/
   
 */
namespace PwnedClient
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// A simple class to communicate with Troy Hunt's
    /// Pwned Passowrds service, using the k-anonymity model
    /// </summary>
    public class PwnedClient
    {
        private readonly HttpClient client;
        private readonly Uri baseUri = new Uri("https://api.pwnedpasswords.com/range/");

        /// <summary>
        /// Create an instance of the PwnedClient using a new HttpClient
        /// </summary>
        public PwnedClient(): this(new HttpClient())
        {

        }
        /// <summary>
        /// Create an instance of the PwnedClient using a provided HttpClient
        /// </summary>
        /// <param name="client"></param>
        public PwnedClient(HttpClient client)
        {
            Guard.ArgumentIsNotNull(client, nameof(client));

            this.client = client;
            this.client.BaseAddress = this.baseUri;
            this.client.DefaultRequestHeaders.Add("api-version", "2");
            this.client.DefaultRequestHeaders.Add("User-Agent", "PwnedClient.Net");
        }
        /// <summary>
        /// Given a password in plain-text, determines whether it has been
        /// compromised in any data breaches
        /// </summary>
        /// <param name="password"></param>
        /// <returns>true/false</returns>
        public bool IsCompromisedPlainTextPassword(string password)
        {
            Guard.ArgumentIsNotNull(password, nameof(password));
            Guard.ArgumentHasMinLength(password, 5, nameof(password));

            var hashedPassword = password.ToSha1Hash();
            return this.IsCompromisedHashedPassword(hashedPassword);
        }

        /// <summary>
        /// Given a SHA1 hashed password, determines whether it has been
        /// compromised in any data breaches
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns>true/false</returns>
        public bool IsCompromisedHashedPassword(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            var suffix = hashedPassword.GetSuffix();

            var results = this.GetSearchResults(hashedPassword.FirstFive());
            return results.Contains(suffix);
        }
        /// <summary>
        /// Given the first 5 characters of a hashed password, return a dictionary
        /// of matched password hashe suffixes and the number of occurrences in data breaches
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns></returns>
        /// <remarks>
        /// Using either of the two GetMatches methods to do your own password checking
        /// without needing to send the full password to this client.
        /// </remarks>
        public Dictionary<string,int> GetMatchesDictionary(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            var results = this.GetMatchesRaw(hashedPassword);
            return this.ResultsAsDictionary(results);
        }

        /// <summary>
        /// Given the first 5 characters of a hashed password, return the raw
        /// string which contains compromised password hash suffixes and occurrence counts
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns></returns>
        /// <remarks>
        /// The quickest to execute of the two GetMatches methods provided.
        /// You can handle the return string as you see fit.
        /// </remarks>
        public string GetMatchesRaw(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

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
            Guard.ArgumentIsNotNull(input, nameof(input));
            Guard.ArgumentHasMinLength(input, 5, nameof(input));

            return input.Substring(5, input.Length - 5);
        }

        public static string FirstFive(this string input)
        {
            Guard.ArgumentIsNotNull(input, nameof(input));
            Guard.ArgumentHasMinLength(input, 5, nameof(input));

            return input.Substring(0, 5);
        }

        public static IEnumerable<string> SplitToLines(this string input)
        {
            if (input == null)
            {
                yield break;
            }

            using (var reader = new StringReader(input))
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