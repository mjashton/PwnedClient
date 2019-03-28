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
    using System.Net.Http;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;

    using global::PwnedClient.Interfaces;

    /// <summary>
    /// A simple class to communicate with Troy Hunt's
    /// Pwned Passowrds service, using the k-anonymity model
    /// </summary>
    [Obsolete("For easier namespacing and async-only methods use the PasswordChecker class instead")]
    public class PwnedClient : IPwnedClient, IPwnedClientAsync
    {
        private readonly PwnedClientBase Base;

        /// <summary>
        /// Create an instance of the PwnedClient using a new HttpClient
        /// </summary>
        public PwnedClient() : this(new HttpClient())
        {
        }
        /// <summary>
        /// Create an instance of the PwnedClient using a provided HttpClient
        /// </summary>
        /// <param name="client"></param>
        public PwnedClient(HttpClient client)  
        {
            this.Base = new PwnedClientBase(client);
        }

        /// <inheritdoc />
        public int GetBreachCount(string password, bool isHashed = false)
        {
            return this.Base.GetBreachCount(password, isHashed);
        }

        /// <inheritdoc />
        public int GetBreachCountHashedPassword(string hashedPassword)
        {
            return this.Base.GetBreachCountHashedPassword(hashedPassword);
        }

        /// <inheritdoc />
        public int GetBreachCountPlainTextPassword(string password)
        {
            return this.Base.GetBreachCountPlainTextPassword(password);
        }

        /// <inheritdoc />
        public Dictionary<string, int> GetMatchesDictionary(string hashedPassword)
        {
            return this.Base.GetMatchesDictionary(hashedPassword);
        }

        /// <inheritdoc />
        public string GetMatchesRaw(string hashedPassword)
        {
            return this.Base.GetMatchesRaw(hashedPassword);
        }

        /// <inheritdoc />
        public bool IsCompromised(string password, bool isHashed = false)
        {
            return this.Base.IsCompromised(password, isHashed);
        }

        /// <inheritdoc />
        public bool IsCompromisedHashedPassword(string hashedPassword)
        {
            return this.Base.IsCompromisedHashedPassword(hashedPassword);
        }

        /// <inheritdoc />
        public bool IsCompromisedPlainTextPassword(string password)
        {
            return this.Base.IsCompromisedPlainTextPassword(password);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountAsync(string password, bool isHashed = false)
        {
            return this.Base.GetBreachCountAsync(password, isHashed);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountHashedPasswordAsync(string hashedPassword)
        {
            return this.Base.GetBreachCountHashedPasswordAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountPlainTextPasswordAsync(string password)
        {
            return this.Base.GetBreachCountPlainTextPasswordAsync(password);
        }

        /// <inheritdoc />
        public Task<Dictionary<string, int>> GetMatchesDictionaryAsync(string hashedPassword)
        {
            return this.Base.GetMatchesDictionaryAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<string> GetMatchesRawAsync(string hashedPassword)
        {
            return this.Base.GetMatchesRawAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedAsync(string password, bool isHashed = false)
        {
            return this.Base.IsCompromisedAsync(password, isHashed);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedHashedPasswordAsync(string hashedPassword)
        {
            return this.Base.IsCompromisedHashedPasswordAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedPlainTextPasswordAsync(string password)
        {
            return this.Base.IsCompromisedPlainTextPasswordAsync(password);
        }
    }

    public static class StringExtensions
    {
        /// <summary>
        /// Hashes the given string using SHA1 
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Returns the input string with the first five
        /// characters removed
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string GetSuffix(this string input)
        {
            Guard.ArgumentIsNotNull(input, nameof(input));
            Guard.ArgumentHasMinLength(input, 5, nameof(input));

            return input.Substring(5);
        }

        /// <summary>
        /// Returns the first five characters of the input string
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        public static string FirstFive(this string input)
        {
            Guard.ArgumentIsNotNull(input, nameof(input));
            Guard.ArgumentHasMinLength(input, 5, nameof(input));

            return input.Substring(0, 5);
        }

        /// <summary>
        /// Splits the input string into an IEnumerable of string
        /// splitting on line breaks
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
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