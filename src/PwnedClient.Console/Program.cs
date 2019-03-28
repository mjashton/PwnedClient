namespace PwnedClient.Console
{
    using Console = System.Console;

    class Program
    {
        static void Main(string[] args)
        {
            var pwdChecker = new PasswordChecker();
            do
            {
                Console.WriteLine("Enter password to test");
                var password = Console.ReadLine();
                var hashedPassword = password.ToSha1Hash();
                var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);

                var results = pwdChecker.GetMatchesDictionaryAsync(hashedPassword).Result;
                var isUnsafe = results.TryGetValue(suffix, out int count);

                Console.WriteLine(
                    isUnsafe ? $"This password has been seen in {count} breaches" : "This password is ok");
                Console.WriteLine();
            } while (true);
        }
    }
}
