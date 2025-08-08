// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using Org.BouncyCastle.Asn1.EdEC;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Adapts a friendly name into an <see cref="Oid"/> instance.
/// Provides cached instances for Ed25519 and Ed448 to avoid repeated allocation and improve consistency.
/// </summary>
public sealed class OidFriendlyNameAdapter : IAdapter<string, Oid>
{
    private static readonly Oid s_ed25519 = new(EdECObjectIdentifiers.id_Ed25519.Id);
    private static readonly Oid s_ed448 = new(EdECObjectIdentifiers.id_Ed448.Id);

    /// <summary>
    /// Gets a default instance of <see cref="OidFriendlyNameAdapter"/>.
    /// </summary>
    public static OidFriendlyNameAdapter Default { get; } = new();

    /// <summary>
    /// Converts the stored friendly name to an <see cref="Oid"/> instance.
    /// Returns cached instances for Ed25519 and Ed448 for performance and reliability.
    /// </summary>
    /// <returns>
    /// The corresponding <see cref="Oid"/> object.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown if the stored friendly name is <see langword="null"/> (prevented by constructor validation).
    /// </exception>
    /// <exception cref="CryptographicException">
    /// Thrown if <see cref="Oid.FromFriendlyName(string, OidGroup)"/> fails,
    /// indicating the friendly name is not recognized.
    /// </exception>
    /// <remarks>
    /// The method uses ordinal string comparison for identifying Ed25519 and Ed448 and relies on 
    /// .NET cryptography APIs for other friendly names.
    /// </remarks>
    public Oid Adapt(string source) => source switch
    {
        var s when string.Equals(s, "Ed25519", StringComparison.Ordinal) => s_ed25519,
        var s when string.Equals(s, "Ed448", StringComparison.Ordinal) => s_ed448,

        _ => Oid.FromFriendlyName(source, OidGroup.All)
    };
}
