// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using PkiFabric.Core.Diagnostics;

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Subject Alternative Name (SAN) Other Name type, which includes a type identifier (OID)
/// and an associated value.
/// </summary>
/// <remarks>
/// The Other Name SAN allows for inclusion of arbitrary types identified by an object identifier (OID)
/// along with their corresponding value, as specified in the SAN extension of a certificate.
/// </remarks>
public sealed class SanOtherName(string value, Oid typeId) : ISubjectAltName
{
    /// <summary>
    /// Gets the string value associated with the Other Name SAN type.
    /// </summary>
    public string Value { get; } = value;
    /// <summary>
    /// Gets the object identifier (OID) that specifies the type of the Other Name.
    /// </summary>
    [LogAsOid]
    public Oid TypeId { get; } = typeId;
}
