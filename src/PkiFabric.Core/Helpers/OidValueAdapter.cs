// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using Org.BouncyCastle.Asn1.EdEC;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Adapts a string representation of an object identifier (OID) into an <see cref="Oid"/> instance,
/// providing cached instances for common EdEC OIDs to avoid repeated allocation.
/// </summary>
public sealed class OidValueAdapter : IAdapter<string, Oid>
{
    private static readonly Oid s_ed25519 = new(EdECObjectIdentifiers.id_Ed25519.Id, "Ed25519");
    private static readonly Oid s_ed448 = new(EdECObjectIdentifiers.id_Ed448.Id, "Ed448");

    /// <summary>
    /// Gets a default instance of <see cref="OidValueAdapter"/>.
    /// </summary>
    public static OidValueAdapter Default { get; } = new();

    /// <summary>
    /// Converts the stored OID string to an <see cref="Oid"/> instance.
    /// </summary>
    /// <returns>
    /// The corresponding <see cref="Oid"/> object. Returns cached instances for well-known Ed25519 and Ed448 OIDs 
    /// to improve performance and ensure consistency.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if the stored OID string is <see langword="null"/> (prevented by constructor validation).
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Thrown if <see cref="Oid.FromOidValue(string, OidGroup)"/> fails to find a matching OID,
    /// indicating the input value is invalid or unrecognized.
    /// </exception>
    /// <remarks>
    /// The method uses exact ordinal comparison for matching known OIDs and relies on .NET cryptography APIs 
    /// to produce the <see cref="Oid"/> instances.  
    /// Be ready to handle exceptions if the OID string is malformed or unsupported.
    /// </remarks>
    public Oid Adapt(string source) => source switch
    {
        var s when string.Equals(s, s_ed25519.Value, StringComparison.Ordinal) => s_ed25519,
        var s when string.Equals(s, s_ed448.Value, StringComparison.Ordinal) => s_ed448,

        _ => Oid.FromOidValue(source, OidGroup.All)
    };
}
