namespace PwnedClient
{
    using System.Net.Http;
    using System.Threading.Tasks;
    
    /// <summary>
    /// A simple class to communicate with Troy Hunt's
    /// Pwned Passowrds service, using the k-anonymity model
    /// </summary>
    public class SimplePasswordChecker
    {
        private readonly PwnedClientBase pwnedClient;

        /// <inheritdoc />
        public SimplePasswordChecker() : this(new HttpClient()){}

        /// <inheritdoc />
        public SimplePasswordChecker(HttpClient client)
        {
            this.pwnedClient = new PwnedClientBase(client);
        }

        /// <summary>
        /// Given a password, determine if it has been compromised
        /// in any data breaches. Use isHashed to indicate that this
        /// password is provided SHA1 hashed
        /// </summary>
        /// <param name="password"></param>
        /// <param name="isHashed"></param>
        /// <returns></returns>
        public Task<bool> IsCompromisedAsync(string password, bool isHashed = false)
        {
            return this.pwnedClient.IsCompromisedAsync(password, isHashed);
        }

    }
}