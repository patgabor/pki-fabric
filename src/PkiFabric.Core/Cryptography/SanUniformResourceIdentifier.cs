// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Subject Alternative Name (SAN) Uniform Resource Identifier (URI).
/// </summary>
/// <remarks>
/// The URI corresponds to a Uniform Resource Identifier used in the SAN extension of a certificate,
/// such as "https://example.com" or "urn:example:object".
/// </remarks>
public sealed class SanUniformResourceIdentifier(string value) : ISubjectAltName
{
    /// <summary>
    /// Gets the URI string representing the Uniform Resource Identifier in the SAN extension.
    /// </summary>
    public string Value { get; } = value;
}
