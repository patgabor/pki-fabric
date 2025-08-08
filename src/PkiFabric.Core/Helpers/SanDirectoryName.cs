// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

public sealed class SanDirectoryName(string distinguishedName) : ISubjectAltName
{
    // like: CN=John Doe, OU=Sales, O=Example Corp, L=Budapest, ST=Budapest, C=HU
    public string DistinguishedName { get; } = distinguishedName;
}
