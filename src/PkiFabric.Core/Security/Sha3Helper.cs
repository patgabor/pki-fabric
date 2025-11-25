// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

namespace PkiFabric.Core.Security;

/// <summary>
/// Provides methods for computing SHA-3 hash values using the Keccak-based sponge construction.
/// SHA-3 is the latest member of the Secure Hash Algorithm family, standardized in 2015.
/// Note: SHA-3 is fundamentally different from SHA-2, and the hash outputs are named SHA3-256, SHA3-384, and SHA3-512.
/// </summary>
public sealed class Sha3Helper : ISha3Helper
{
    /// <inheritdoc />
    public byte[] ComputeSha256(ReadOnlySpan<byte> bytes) => SHA3_256.HashData(bytes);
    /// <inheritdoc />
    public byte[] ComputeSha384(ReadOnlySpan<byte> bytes) => SHA3_384.HashData(bytes);
    /// <inheritdoc />
    public byte[] ComputeSha512(ReadOnlySpan<byte> bytes) => SHA3_512.HashData(bytes);
}
