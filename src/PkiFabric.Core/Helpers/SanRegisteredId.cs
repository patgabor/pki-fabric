// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using PkiFabric.Core.Diagnostics;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Represents a Subject Alternative Name (SAN) Registered ID, identified by an object identifier (OID).
/// </summary>
/// <remarks>
/// The Registered ID SAN type allows inclusion of a globally unique identifier specified by an OID
/// in the SAN extension of a certificate.
/// </remarks>
public sealed class SanRegisteredId(Oid value) : ISubjectAltName
{
    /// <summary>
    /// Gets the object identifier (OID) representing the registered ID in the SAN extension.
    /// </summary>
    [LogAsOid]
    public Oid Value { get; } = value;
}
