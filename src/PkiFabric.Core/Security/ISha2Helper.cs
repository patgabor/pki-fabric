// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Security;

/// <summary>
/// Provides methods for computing 'classic' SHA-2 hash values—specifically SHA-256, SHA-384, and SHA-512.
/// SHA-2 is the established second generation of the Secure Hash Algorithm family, published in 2001.
/// Note: SHA-3 is newer (published in 2015) and uses a fundamentally different construction.
/// </summary>
public interface ISha2Helper
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
