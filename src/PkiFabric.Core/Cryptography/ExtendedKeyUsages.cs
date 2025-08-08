// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents common Extended Key Usage (EKU) purposes for X.509 certificates.
/// These values correspond to standard EKU object identifiers (OIDs) used to define
/// the intended purpose of a certificate's public key.
/// </summary>
public enum ExtendedKeyUsages
{
    /// <summary>
    /// Any extended key usage is acceptable (OID: 2.5.29.37.0).
    /// </summary>
    Any,

    /// <summary>
    /// Server authentication for TLS/SSL connections (OID: 1.3.6.1.5.5.7.3.1).
    /// </summary>
    ServerAuth,

    /// <summary>
    /// Client authentication for TLS/SSL connections (OID: 1.3.6.1.5.5.7.3.2).
    /// </summary>
    ClientAuth,

    /// <summary>
    /// Code signing to verify the integrity and origin of software (OID: 1.3.6.1.5.5.7.3.3).
    /// </summary>
    CodeSigning,

    /// <summary>
    /// Secure email protection, including signing and encryption (OID: 1.3.6.1.5.5.7.3.4).
    /// </summary>
    EmailProtection,

    /// <summary>
    /// Trusted timestamping to prove data existed at a certain time (OID: 1.3.6.1.5.5.7.3.8).
    /// </summary>
    TimeStamping,
}
