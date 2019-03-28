# PwnedClient
This is a simple client for accessing the Pwned Passwords service offered for free by the amazing Troy Hunt of https://haveibeenpwned.com.
If you don't know why you should be using this service then read [this blog post][1] from Troy.

If you intend to use this client then please make sure you agree with the [Acceptable Use][2] policy and license for the service.

This client uses version 2 of the interface which means that **the password is not sent across the wire** to perform the check of whether it has been involved in a security breach. It uses a *k-Anonymity* model, which means that only the first 5 characters of the hashed password are submitted to the service. The reply from the service will be a list of roughly 400 to 600 breached password hashes that match on those 5 characters, and so the caller of the service can then check that list for the presence of the complete password hash.

### Constructing the client
There are two constructors available: a default constructor which will spin up its own instance of an `HttpClient`, and another that allows you to pass your own `HttpClient`.

```c#
public PasswordChecker()
public PasswordChecker(HttpClient client)
```

Depending on your requirements, this client provides a number of ways to access the service.

### Let the client do the work
*Note: the complete password is not sent across the wire to the service. Even if you use a method that requires a complete password it is just used by this client to inform you on whether it has been compromised in a breach*.

These methods provide the most convenience and the least information:  informing you of whether the provided password has been compromised or not.

##### Plain or Hashed password
Find out whether a password is listed in a breach dataset
```c#
public bool IsCompromised(string password, bool isHashed = false)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
bool isUnsafe = pwdChecker.IsCompromised("p@55w0rd");
bool isUnsafe2 = pwdChecker.IsCompromised("p@55w0rd".ToSha1Hash(), true);
```

##### Find out how compromised a password is
Get a count indicating how many breach data sets the password appears in.
```c#
public int GetBreachCount(string password, bool isHashed = false)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
var count = pwdChecker.GetBreachCount("p@55w0rd");
var count2 = pwdChecker.GetBreachCount("p@55w0rd".ToSha1Hash(), true);
```

##### Plain text password
An explicit method for plain text password checking.
```c#
public bool IsCompromisedPlainTextPassword(string password)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
bool isUnsafe = pwdChecker.IsCompromisedPlainTextPassword("p@55w0rd");
```

An explicit method for getting the breach count of a plain text password
```c#
public int GetBreachCountPlainTextPassword(string password)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
var count = pwdChecker.GetBreachCountPlainTextPassword("p@55w0rd");
```

##### Hashed password
An explicit method for hashed password checking.
You can provide the SHA1 hashed password, or make use of the provided extension method.

```c#
public bool IsCompromisedHashedPassword(string hashedPassword)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
bool isUnsafe = pwdChecker.IsCompromisedHashedPassword("p@55w0rd".ToSha1Hash());
```

An explicit method for getting the breach count of a hashedpassword
```c#
public int GetBreachCountHashedPassword(string hashedPassword)
```
e.g.
```c#
var pwdChecker = new PasswordChecker();
var count = pwdChecker.GetBreachCountHashedPassword("p@55w0rd".ToSha1Hash());
```

### You do the work
If you want to do your own heavy lifting, in terms of working out whether the password has been breached, you can use the following methods for returning the compromised password hashes that match the first 5 characters of your hashed password. Both methods require a hashed password, and you can provide either a complete hashed password or just the first 5 characters from the hashed password. *Even if you provide the complete password only the first 5 characters are sent to the service*.

##### Get a dictionary returned
```c#
public Dictionary<string,int> GetMatchesDictionary(string hashedPassword)
```
This will return a dictionary of all the *suffixes* of compromised hashed passwords that share the first 5 characters with your submitted hashed password, along with a prevalence count of how many times it appears in the dataset. You can then work out if your hashed password appears in this list, and maybe use the prevalence count to decide whether it is a safe password to use. Personally, any appearance in the breach dataset would be enough to stop me wanting to use that password.

e.g.
```c#
var pwdChecker = new PasswordChecker();
var password = "password123";
var hashedPassword = password.ToSha1Hash();
var firstFive = hashedPassword.Substring(0, 5);
var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
var result = pwdChecker.GetMatchesDictionary(firstFive);
bool isUnsafe = result.ContainsKey(suffix);
```

##### Get raw results returned
```c#
public string GetMatchesRaw(string hashedPassword)
```
This will return a string, with each line consisting of the matched *suffix* and prevalence count separated by a colon :

For example
>0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:1
012A7CA357541F0AC487871FEEC1891C49C:2
0136E006E24E7D152139815FB0FC6A50B15:2
...

You can then use this raw data as you see fit.

e.g.
```c#
var pwdChecker = new PasswordChecker();
var password = "password123";
var hashedPassword = password.ToSha1Hash();
var firstFive = hashedPassword.Substring(0, 5);
var suffix = hashedPassword.Substring(5, hashedPassword.Length - 5);
var result = this.passwordChecker.GetMatchesRaw(firstFive);
bool isUnsafe = result.Contains(suffix);
```

[1]:https://www.troyhunt.com/introducing-306-million-freely-downloadable-pwned-passwords/
[2]:https://haveibeenpwned.com/API/v2#AcceptableUse
