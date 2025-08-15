// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Security;

/// <summary>
/// Provides methods for computing SHA-3 hash values using the Keccak-based sponge construction.
/// SHA-3 is the latest member of the Secure Hash Algorithm family, standardized in 2015.
/// Note: SHA-3 is fundamentally different from SHA-2, and the hash outputs are named SHA3-256, SHA3-384, and SHA3-512.
/// </summary>
public interface ISha3Helper
{
    /// <summary>
    /// Computes the SHA-256 hash of the given byte sequence.
    /// </summary>
    byte[] ComputeSha256(ReadOnlySpan<byte> bytes);
    /// <summary>
    /// Computes the SHA-384 hash of the given byte sequence.
    /// </summary>
    byte[] ComputeSha384(ReadOnlySpan<byte> bytes);
    /// <summary>
    /// Computes the SHA-512 hash of the given byte sequence.
    /// </summary>
    byte[] ComputeSha512(ReadOnlySpan<byte> bytes);
}
