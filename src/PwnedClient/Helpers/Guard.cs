namespace PwnedClient
{
    using System;
    using System.Diagnostics;
    using global::PwnedClient.Interfaces;

    /// <summary>
    /// Some simple guard clauses
    /// </summary>
    public static class Guard
    {
        [DebuggerHidden]
        public static void ArgumentHasMinLength(string value, int minLength, string argument)
        {
            if (value.Length < minLength) throw new ArgumentException($"{argument} needs minimum length of {minLength}");
        }
        [DebuggerHidden]
        public static void ArgumentIsNotNull(object value, string argument)
        {
            if (value == null) throw new ArgumentNullException(argument);
        }
    }
}