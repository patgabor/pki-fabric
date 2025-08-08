// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Represents a Subject Alternative Name (SAN) DNS name.
/// </summary>
/// <remarks>
/// The DNS name corresponds to a domain name used in the SAN extension of a certificate, e.g., "example.com".
/// </remarks>
public sealed class SanDnsName(string value) : ISubjectAltName
{
    /// <summary>
    /// Gets the DNS name string representing the DNS name in the SAN extension.
    /// </summary>
    public string Value { get; } = value;
}
