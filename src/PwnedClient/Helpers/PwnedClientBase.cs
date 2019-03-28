namespace PwnedClient
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Net.Http;
    using System.Threading.Tasks;
    using global::PwnedClient.Interfaces;
    internal class PwnedClientBase : IPwnedClient, IPwnedClientAsync
    {
        private HttpClient client;
        private readonly Uri baseUri = new Uri("https://api.pwnedpasswords.com/range/");

        public PwnedClientBase(): this(new HttpClient())
        {

        }

        public PwnedClientBase(HttpClient client)
        {
            Guard.ArgumentIsNotNull(client, nameof(client));

            this.client = client;
            this.client.BaseAddress = this.baseUri;
            this.client.DefaultRequestHeaders.Add("api-version", "2");
            this.client.DefaultRequestHeaders.Add("User-Agent", "PwnedClient.Net");
        }

        /// <inheritdoc />
        public bool IsCompromised(string password, bool isHashed = false)
        {
            return this.IsCompromisedAsync(password, isHashed).Result;
        }

        /// <inheritdoc />
        public async Task<bool> IsCompromisedAsync(string password, bool isHashed = false)
        {
            return isHashed
                ? await this.IsCompromisedHashedPasswordAsync(password)
                : await this.IsCompromisedPlainTextPasswordAsync(password);
        }

        /// <inheritdoc />
        public bool IsCompromisedPlainTextPassword(string password)
        {
            return this.IsCompromisedPlainTextPasswordAsync(password).Result;

        }

        /// <inheritdoc />
        public async Task<bool> IsCompromisedPlainTextPasswordAsync(string password)
        {
            Guard.ArgumentIsNotNull(password, nameof(password));
            Guard.ArgumentHasMinLength(password, 5, nameof(password));

            var hashedPassword = password.ToSha1Hash();
            return await this.IsCompromisedHashedPasswordAsync(hashedPassword);
        }

        /// <inheritdoc />
        public bool IsCompromisedHashedPassword(string hashedPassword)
        {
            return this.IsCompromisedHashedPasswordAsync(hashedPassword).Result;
        }

        /// <inheritdoc />
        public async Task<bool> IsCompromisedHashedPasswordAsync(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            var suffix = hashedPassword.GetSuffix();
            var results = await this.GetSearchResultsAsync(hashedPassword.FirstFive());
            return results.Contains(suffix);
        }

        /// <inheritdoc />
        public int GetBreachCount(string password, bool isHashed = false)
        {
            return this.GetBreachCountAsync(password, isHashed).Result;
        }

        /// <inheritdoc />
        public async Task<int> GetBreachCountAsync(string password, bool isHashed = false)
        {
            return isHashed
                ? await this.GetBreachCountHashedPasswordAsync(password)
                : await this.GetBreachCountPlainTextPasswordAsync(password);
        }

        /// <inheritdoc />
        public int GetBreachCountPlainTextPassword(string password)
        {
            return this.GetBreachCountPlainTextPasswordAsync(password).Result;
        }

        /// <inheritdoc />
        public async Task<int> GetBreachCountPlainTextPasswordAsync(string password)
        {
            Guard.ArgumentIsNotNull(password, nameof(password));
            Guard.ArgumentHasMinLength(password, 5, nameof(password));

            var hashedPassword = password.ToSha1Hash();
            var suffix = hashedPassword.GetSuffix();
            var results = await this.GetMatchesDictionaryAsync(hashedPassword);
            var isCompromised = results.TryGetValue(suffix, out int count);
            return isCompromised ? count : 0;
        }

        /// <inheritdoc />
        public int GetBreachCountHashedPassword(string hashedPassword)
        {
            return this.GetBreachCountHashedPasswordAsync(hashedPassword).Result;
        }

        /// <inheritdoc />
        public async Task<int> GetBreachCountHashedPasswordAsync(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            var suffix = hashedPassword.GetSuffix();
            var results = await this.GetMatchesDictionaryAsync(hashedPassword);
            var isCompromised = results.TryGetValue(suffix, out int count);
            return isCompromised ? count : 0;
        }

        /// <inheritdoc />
        public Dictionary<string, int> GetMatchesDictionary(string hashedPassword)
        {
            return this.GetMatchesDictionaryAsync(hashedPassword).Result;
        }

        /// <inheritdoc />
        public async Task<Dictionary<string, int>> GetMatchesDictionaryAsync(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            var results = await this.GetMatchesRawAsync(hashedPassword);
            return this.ResultsAsDictionary(results);
        }

        /// <inheritdoc />
        public string GetMatchesRaw(string hashedPassword)
        {
            return this.GetMatchesRawAsync(hashedPassword).Result;
        }

        /// <inheritdoc />
        public async Task<string> GetMatchesRawAsync(string hashedPassword)
        {
            Guard.ArgumentIsNotNull(hashedPassword, nameof(hashedPassword));
            Guard.ArgumentHasMinLength(hashedPassword, 5, nameof(hashedPassword));

            return await this.GetSearchResultsAsync(hashedPassword.FirstFive());
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

        private async Task<string> GetSearchResultsAsync(string searchUri)
        {
            var response = await this.client.GetAsync(searchUri);
            var results = await response.Content.ReadAsStringAsync();
            return results;
        }
    }
}