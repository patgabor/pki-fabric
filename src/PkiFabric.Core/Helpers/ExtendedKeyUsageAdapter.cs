// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Immutable;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

using PkiFabric.Core.Cryptography;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Adapts an <see cref="ImmutableHashSet{T}"/> of <see cref="ExtendedKeyUsages"/> 
/// into a BouncyCastle <see cref="Asn1EncodableVector"/> containing the 
/// corresponding <see cref="KeyPurposeID"/> entries for use in X.509 extended key usage extensions.
/// </summary>
public sealed class ExtendedKeyUsageAdapter : IAdapter<ImmutableHashSet<ExtendedKeyUsages>, Asn1EncodableVector>
{
    /// <summary>
    /// Gets a default instance of <see cref="ExtendedKeyUsageAdapter"/>.
    /// </summary>
    public static ExtendedKeyUsageAdapter Default { get; } = new();

    /// <inheritdoc/>
    public Asn1EncodableVector Adapt(ImmutableHashSet<ExtendedKeyUsages> source)
    {
        Asn1EncodableVector extendedKeyUsages = [];

        foreach (ExtendedKeyUsages usage in source)
        {
            switch (usage)
            {
                case ExtendedKeyUsages.Any:
                    extendedKeyUsages.Add(KeyPurposeID.AnyExtendedKeyUsage);
                    break;

                case ExtendedKeyUsages.ServerAuth:
                    extendedKeyUsages.Add(KeyPurposeID.id_kp_serverAuth);
                    break;

                case ExtendedKeyUsages.ClientAuth:
                    extendedKeyUsages.Add(KeyPurposeID.id_kp_clientAuth);
                    break;

                case ExtendedKeyUsages.CodeSigning:
                    extendedKeyUsages.Add(KeyPurposeID.id_kp_codeSigning);
                    break;

                case ExtendedKeyUsages.EmailProtection:
                    extendedKeyUsages.Add(KeyPurposeID.id_kp_emailProtection);
                    break;

                case ExtendedKeyUsages.TimeStamping:
                    extendedKeyUsages.Add(KeyPurposeID.id_kp_timeStamping);
                    break;

                default:
                    throw new InvalidOperationException($"Unsupported Extended Key Usage {usage}.");
            }
        }
        return extendedKeyUsages;
    }
}
