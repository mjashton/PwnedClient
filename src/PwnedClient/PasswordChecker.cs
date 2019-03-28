namespace PwnedClient
{
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Threading.Tasks;

    using global::PwnedClient.Interfaces;

    /// <summary>
    /// A class to communicate with Troy Hunt's
    /// Pwned Passowrds service, using the k-anonymity model
    /// </summary>
    public class PasswordChecker : IPwnedClientAsync
    {
        private readonly PwnedClientBase pwnedClient;

        /// <inheritdoc />
        public PasswordChecker() : this(new HttpClient()){}

        /// <inheritdoc />
        public PasswordChecker(HttpClient client)
        {
            this.pwnedClient = new PwnedClientBase(client);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountAsync(string password, bool isHashed = false)
        {
            return this.pwnedClient.GetBreachCountAsync(password, isHashed);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountHashedPasswordAsync(string hashedPassword)
        {
            return this.pwnedClient.GetBreachCountHashedPasswordAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<int> GetBreachCountPlainTextPasswordAsync(string password)
        {
            return this.pwnedClient.GetBreachCountPlainTextPasswordAsync(password);
        }

        /// <inheritdoc />
        public Task<Dictionary<string, int>> GetMatchesDictionaryAsync(string hashedPassword)
        {
            return this.pwnedClient.GetMatchesDictionaryAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<string> GetMatchesRawAsync(string hashedPassword)
        {
            return this.pwnedClient.GetMatchesRawAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedAsync(string password, bool isHashed = false)
        {
            return this.pwnedClient.IsCompromisedAsync(password, isHashed);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedHashedPasswordAsync(string hashedPassword)
        {
            return this.pwnedClient.IsCompromisedHashedPasswordAsync(hashedPassword);
        }

        /// <inheritdoc />
        public Task<bool> IsCompromisedPlainTextPasswordAsync(string password)
        {
            return this.pwnedClient.IsCompromisedPlainTextPasswordAsync(password);
        }
    }
}