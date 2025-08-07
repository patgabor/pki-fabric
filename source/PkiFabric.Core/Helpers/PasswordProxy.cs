// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Org.BouncyCastle.OpenSsl;

namespace PkiFabric.Core.Helpers;

internal sealed class PasswordProxy(string password) : IPasswordFinder
{
    private readonly string _password = password;
    public char[] GetPassword() => _password.ToCharArray();
}
