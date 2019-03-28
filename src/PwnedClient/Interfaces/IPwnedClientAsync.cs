namespace PwnedClient.Interfaces
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IPwnedClientAsync
    {
        /// <summary>
        /// Gets the prevalence count for how often this password
        /// appears in breach data. Use isHashed to indicate that 
        /// the given password has been SHA1 hashed
        /// </summary>
        /// <param name="password"></param>
        /// <param name="isHashed"></param>
        /// <returns></returns>
        Task<int> GetBreachCountAsync(string password, bool isHashed = false);

        /// <summary>
        /// Gets the prevalence count for how often the given
        /// SHA1 hashed password appears in breach data.
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns></returns>
        Task<int> GetBreachCountHashedPasswordAsync(string hashedPassword);

        /// <summary>
        /// Gets the prevalence count for how often the given
        /// plain text password appears in breach data.
        /// </summary>
        /// <param name="password"></param>
        /// <returns></returns>
        Task<int> GetBreachCountPlainTextPasswordAsync(string password);

        /// <summary>
        /// Given the first 5 characters of a hashed password, return a dictionary
        /// of matched password hash suffixes and the number of occurrences in data breaches
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns></returns>
        /// <remarks>
        /// Using either of the two GetMatches methods to do your own password checking
        /// without needing to send the full password to this client.
        /// </remarks>
        Task<Dictionary<string, int>> GetMatchesDictionaryAsync(string hashedPassword);

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
        Task<string> GetMatchesRawAsync(string hashedPassword);

        /// <summary>
        /// Given a password, determine if it has been compromised
        /// in any data breaches. Use isHashed to indicate that this
        /// password is provided SHA1 hashed
        /// </summary>
        /// <param name="password"></param>
        /// <param name="isHashed"></param>
        /// <returns></returns>
        Task<bool> IsCompromisedAsync(string password, bool isHashed = false);

        /// <summary>
        /// Given a SHA1 hashed password, determines whether it has been
        /// compromised in any data breaches
        /// </summary>
        /// <param name="hashedPassword"></param>
        /// <returns>true/false</returns>
        Task<bool> IsCompromisedHashedPasswordAsync(string hashedPassword);

        /// <summary>
        /// Given a password in plain-text, determines whether it has been
        /// compromised in any data breaches
        /// </summary>
        /// <param name="password"></param>
        /// <returns>true/false</returns>
        Task<bool> IsCompromisedPlainTextPasswordAsync(string password);
    }
}