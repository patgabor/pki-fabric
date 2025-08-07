using Org.BouncyCastle.OpenSsl;

namespace PkiFabric.Core.Helpers;

internal sealed class PasswordProxy(string password) : IPasswordFinder
{
    private readonly string _password = password;
    public char[] GetPassword() => _password.ToCharArray();
}
