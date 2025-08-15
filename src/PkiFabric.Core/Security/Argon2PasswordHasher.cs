// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using CommunityToolkit.Diagnostics;

using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;

namespace PkiFabric.Core.Security;

/// <summary>
/// Argon2id password hasher with secure defaults and clear separation of salt and hash.
/// </summary>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    // Security parameters (tune memory and iterations per your environment)
    private const int SaltLength = 16;          // bytes
    private const int HashLength = 32;          // bytes (256 bits)
    private const int MemoryKb = 64 * 1024;     // 64 MB
    private const int Iterations = 3;           // 3–5 is recommended
    private const int Parallelism = 2;          // threads

    /// <inheritdoc/>
    public (byte[] Salt, byte[] Hash) Hash(string password)
    {
        Guard.IsNotNullOrEmpty(password);

        byte[] salt = GenerateSalt();
        byte[] hash = ComputeHash(password, salt);
        return (Salt: salt, Hash: hash);
    }

    /// <inheritdoc/>
    public bool Verify(string password, (byte[] Salt, byte[] Hash) data)
    {
        Guard.IsNotNullOrEmpty(password);

        (byte[] salt, byte[] hash) = data;

        Guard.IsEqualTo(salt.Length, SaltLength);
        Guard.IsEqualTo(hash.Length, HashLength);

        byte[] computed = ComputeHash(password, salt);

        return CryptographicOperations.FixedTimeEquals(computed, hash);
    }

    private static byte[] GenerateSalt()
    {
        using CryptoApiRandomGenerator randomGenerator = new();
        byte[] salt = new byte[SaltLength];
        randomGenerator.NextBytes(salt);
        return salt;
    }

    private static byte[] ComputeHash(string password, byte[] salt)
    {
        // Build Argon2id parameters
        Argon2Parameters parameters = new Argon2Parameters.Builder(Argon2Parameters.Argon2id)
            .WithSalt(salt)
            .WithParallelism(Parallelism)
            .WithMemoryAsKB(MemoryKb)
            .WithIterations(Iterations)
            .Build();

        Argon2BytesGenerator generator = new();
        generator.Init(parameters);

        byte[] result = new byte[HashLength];

        _ = generator.GenerateBytes(password.ToCharArray(), result);
        return result;
    }
}
