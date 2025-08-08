// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Represents a Subject Alternative Name (SAN) directory name using a distinguished name string.
/// </summary>
/// <remarks>
/// The distinguished name should be in the format of a comma-separated list of attribute=value pairs, 
/// for example: "CN=John Doe, OU=Sales, O=Example Corp, L=Budapest, ST=Budapest, C=HU".
/// </remarks>
public sealed class SanDirectoryName(string distinguishedName) : ISubjectAltName
{
    /// <summary>
    /// Gets the distinguished name string representing the directory name in the SAN extension.
    /// </summary>
    public string DistinguishedName { get; } = distinguishedName;
}
