// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

namespace PkiFabric.Core.Security;

/// <summary>
/// Defines a secure password hasher using Argon2id.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>
    /// Hashes a password and returns its salt and hash.
    /// </summary>
    /// <param name="password">The password as UTF-8 bytes.</param>
    /// <returns>
    /// A tuple containing:
    ///   • Salt: cryptographically random salt.  
    ///   • Hash: Argon2id-derived hash.  
    /// </returns>
    (byte[] Salt, byte[] Hash) Hash(string password);

    /// <summary>
    /// Verifies a password against a stored salt and hash.
    /// </summary>
    /// <param name="password">The password as UTF-8 bytes.</param>
    /// <param name="data">The stored salt and hash.</param>
    /// <returns>True if the password is valid; otherwise, false.</returns>
    /// <remarks>
    /// This method compares two buffers' contents for equality in a manner which does not
    /// leak timing information, making it ideal for use within cryptographic routines. See details: <see cref="CryptographicOperations.FixedTimeEquals"/>
    /// </remarks>
    bool Verify(string password, (byte[] Salt, byte[] Hash) data);
}
