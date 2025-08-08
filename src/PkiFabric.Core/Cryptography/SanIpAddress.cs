// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Net;

using Destructurama.Attributed;

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Subject Alternative Name (SAN) IP address.
/// </summary>
/// <remarks>
/// The IP address corresponds to an IP address used in the SAN extension of a certificate.
/// This can be either IPv4 or IPv6 format.
/// </remarks>
public sealed class SanIpAddress(IPAddress value) : ISubjectAltName
{
    /// <summary>
    /// Gets the IP address representing the IP address in the SAN extension.
    /// </summary>
    [LogAsScalar]
    public IPAddress Value { get; } = value;
}
