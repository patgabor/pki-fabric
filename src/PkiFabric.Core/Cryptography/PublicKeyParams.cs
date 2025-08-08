// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using PkiFabric.Core.Diagnostics;

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Public key params class that encapsulates the algorithm and key length of a public key.
/// </summary>
public sealed class PublicKeyParams(Oid algorithm, int keyLength)
{
    /// <summary>
    /// Gets the OID representing the algorithm of the public key.
    /// </summary>
    [LogAsOid]
    public Oid Algorithm { get; } = algorithm;
    /// <summary>
    /// Gets the asymmetric key parameter representing the public key.
    /// </summary>
    public int KeyLength { get; } = keyLength;
}
