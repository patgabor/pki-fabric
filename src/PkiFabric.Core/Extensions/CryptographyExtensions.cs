// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;

using PkiFabric.Core.Cryptography;
using PkiFabric.Core.Helpers;

using static System.Security.Cryptography.X509Certificates.DSACertificateExtensions;
using static System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions;
using static System.Security.Cryptography.X509Certificates.RSACertificateExtensions;

using Oid = System.Security.Cryptography.Oid;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;
using X509Certificate2 = System.Security.Cryptography.X509Certificates.X509Certificate2;

namespace PkiFabric.Core.Extensions;

/// <summary>
/// Provides extension methods for parsing cryptographic data from PEM-encoded strings.
/// </summary>
public static class CryptographyExtensions
{
    /// <summary>
    /// Converts a BouncyCastle <see cref="X509Certificate"/> to a .NET <see cref="X509Certificate2"/>.
    /// </summary>
    public static X509Certificate2 ToX509Certificate2(this X509Certificate @this, AsymmetricKeyParameter? privateKey = null)
    {
        if (privateKey is null)
        {
            return new X509Certificate2(@this.CertificateStructure.GetEncoded(Asn1Encodable.Der));
        }
        // TODO: Handle private key if provided
        // may convert to pfx then read into X509Certificate2
        byte[] encoded = @this.GetEncoded();
        return new X509Certificate2(encoded);
    }

    /// <summary>
    /// Computes the SHA-1 thumbprint of the given certificate using BouncyCastle's digest.
    /// Throws if the certificate cannot be encoded.
    /// </summary>
    /// <param name="this">The certificate to hash.</param>
    public static byte[] GetThumbprint(this X509Certificate @this)
    {
        try
        {
            byte[] encoded = @this.GetEncoded();

            if (encoded.Length == 0)
            {
                throw new InvalidOperationException("Certificate encoding returned no data.");
            }

            Sha1Digest digest = new();
            digest.BlockUpdate(encoded, 0, encoded.Length);

            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);

            return output;
        }
        catch (CertificateEncodingException ex)
        {
            throw new InvalidOperationException("Failed to encode certificate to DER format.", ex);
        }
    }

    /// <summary>
    /// Attempts to parse a PFX/PKCS#12 byte array into an immutable dictionary
    /// mapping BouncyCastle X509Certificates to their corresponding private keys (or null).
    /// </summary>
    /// <param name="this">The PFX file as a byte array.</param>
    /// <param name="password">The PFX password.</param>
    /// <param name="certificates">Immutable dictionary of certificate/private key pairs (null key if none found).</param>
    /// <returns>True on success, false if parsing fails.</returns>
    public static bool TryParsePkcs12(
        [NotNullWhen(true)] this byte[] @this,
        string? password,
        out ImmutableDictionary<X509Certificate, AsymmetricKeyParameter?> certificates)
    {
        ImmutableDictionaryBuilder<X509Certificate, AsymmetricKeyParameter?> builder = [];
        if (@this is null || @this.Length == 0)
        {
            certificates = builder.ToImmutable();
            return false; // Fail early if input is invalid
        }

        using var stream = new MemoryStream(@this);
        Pkcs12Store store = new Pkcs12StoreBuilder().Build();
        store.Load(stream, password?.ToCharArray());
        foreach (string alias in store.Aliases)
        {
            if (store.IsKeyEntry(alias))
            {
                X509CertificateEntry certificateEntry = store.GetCertificate(alias);
                X509Certificate certificate = certificateEntry.Certificate;
                AsymmetricKeyEntry keyEntry = store.GetKey(alias);
                AsymmetricKeyParameter privateKey = keyEntry.Key;

                builder[certificate] = privateKey;
            }
            else if (store.IsCertificateEntry(alias))
            {
                X509CertificateEntry entry = store.GetCertificate(alias);
                X509Certificate certificate = entry.Certificate;
                builder[certificate] = null;

            }
        }

        certificates = builder.ToImmutable();
        return true;
    }

    /// <summary>
    /// Attempts to parse a PEM-encoded string into a <see cref="Pkcs10CertificationRequest"/> object.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing a PKCS#10 certification request.</param>
    /// <param name="certificationRequest">When this method returns, contains the parsed <see cref="Pkcs10CertificationRequest"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a <see cref="Pkcs10CertificationRequest"/>; otherwise, <c>false</c>.</returns>
    public static bool TryParseToPkcs10(
        [NotNullWhen(true)] this string? @this,
        [NotNullWhen(true)] out Pkcs10CertificationRequest? certificationRequest)
    {
        if (string.IsNullOrEmpty(@this))
        {
            certificationRequest = null;
            return false;
        }

        try
        {
            using StringReader reader = new(@this);
            PemReader pemReader = new(reader);

            certificationRequest = pemReader.ReadObject() as Pkcs10CertificationRequest;
            return certificationRequest is not null;
        }
        catch (Exception x) when (x is PemException or IOException)
        {
            certificationRequest = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to parse a PEM-encoded string into an X.509 <see cref="X509Certificate"/> object.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing an X.509 certificate.</param>
    /// <param name="certificate">When this method returns, contains the parsed <see cref="X509Certificate"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a certificate; otherwise, <c>false</c>.</returns>
    public static bool TryParseToCertificate(
        [NotNullWhen(true)] this string? @this,
        [NotNullWhen(true)] out X509Certificate? certificate)
    {
        if (string.IsNullOrEmpty(@this))
        {
            certificate = null;
            return false;
        }

        try
        {
            using StringReader reader = new(@this);
            PemReader pemReader = new(reader);

            certificate = pemReader.ReadObject() as X509Certificate;
            return certificate is not null;
        }
        catch (Exception x) when (x is PemException or IOException)
        {
            certificate = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to parse a PEM-encoded string into a public key as an <see cref="AsymmetricKeyParameter"/>.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing a public key.</param>
    /// <param name="publicKey">When this method returns, contains the parsed <see cref="AsymmetricKeyParameter"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a public key; otherwise, <c>false</c>.</returns>
    public static bool TryParseToPublicKey(
        [NotNullWhen(true)] this string? @this,
        [NotNullWhen(true)] out AsymmetricKeyParameter? publicKey)
    {
        if (string.IsNullOrEmpty(@this))
        {
            publicKey = null;
            return false;
        }

        try
        {
            using StringReader reader = new(@this);
            PemReader pemReader = new(reader);

            publicKey = pemReader.ReadObject() as AsymmetricKeyParameter;
            return publicKey is not null;
        }
        catch (Exception x) when (x is PemException or IOException)
        {
            publicKey = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to parse a PEM-encoded string into a private key pair as an <see cref="AsymmetricCipherKeyPair"/>.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing a private key.</param>
    /// <param name="password">An optional password to decrypt the private key if it is encrypted; can be null for unencrypted keys.</param>
    /// <param name="privateKey">When this method returns, contains the parsed <see cref="AsymmetricCipherKeyPair"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a private key; otherwise, <c>false</c>.</returns>
    public static bool TryParseToPrivateKey(
        [NotNullWhen(true)] this string? @this,
        string? password,
        [NotNullWhen(true)] out AsymmetricCipherKeyPair? privateKey)
    {
        if (string.IsNullOrEmpty(@this))
        {
            privateKey = null;
            return false;
        }

        try
        {
            using StringReader reader = new(@this);

            switch (password)
            {
                case null:
                {
                    PemReader pemReader = new(reader);
                    privateKey = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                    return privateKey is not null;
                }

                default:
                {
                    using PasswordProxy passwordProxy = new(password);
                    PemReader pemReader = new(reader, passwordProxy);
                    privateKey = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                    return privateKey is not null;
                }
            }
        }
        catch (Exception x) when (x is PasswordException or PemException or IOException)
        {
            privateKey = null;
            return false;
        }
    }

    /// <summary>
    /// Attempts to extract subject Distinguished Names (DN) from a PKCS#10 certification request.
    /// </summary>
    public static ImmutableDictionary<Oid, ImmutableArray<string>> GetSubject(this Pkcs10CertificationRequest @this)
    {
        ImmutableDictionaryBuilder<Oid, ImmutableArray<string>> builder =
            new(OidEqualityComparer.Default);

        CertificationRequestInfo certificationRequestInfo = @this.GetCertificationRequestInfo();
        IList<DerObjectIdentifier> oids = certificationRequestInfo.Subject.GetOidList();

        foreach (DerObjectIdentifier oid in oids)
        {
            IList<string> values = certificationRequestInfo.Subject.GetValueList(oid);
            builder.Add(new Oid(oid.Id), [.. values]);
        }

        return builder.ToImmutable();
    }

    /// <summary>
    /// Attempts to get the public key algorithm OID from a PKCS#10 certification request.
    /// </summary>
    public static Oid GetPublicKeyAlgorithm(this Pkcs10CertificationRequest @this)
    {
        CertificationRequestInfo certificationRequestInfo = @this.GetCertificationRequestInfo();
        SubjectPublicKeyInfo subjectPublicKeyInfo = certificationRequestInfo.SubjectPublicKeyInfo;
        AlgorithmIdentifier algorithmIdentifier = subjectPublicKeyInfo.Algorithm;
        DerObjectIdentifier oid = algorithmIdentifier.Algorithm;

        return new Oid(oid.Id);
    }
    /// <summary>
    /// Attempts to get the signature algorithm OID from a PKCS#10 certification request.
    /// </summary>
    /// <param name="this">The certification request.</param>
    /// <param name="algorithm">When this method returns, contains the signature algorithm OID if successfully retrieved; otherwise, null.</param>
    /// <returns><c>true</c> if the signature algorithm was successfully retrieved; otherwise, <c>false</c>.</returns>
    public static bool TryGetSignatureAlgorithm(
        [NotNullWhen(true)] this Pkcs10CertificationRequest? @this,
        [NotNullWhen(true)] out Oid? algorithm)
    {
        if (@this is null)
        {
            algorithm = null;
            return false;
        }

        AlgorithmIdentifier algorithmIdentifier = @this.SignatureAlgorithm;
        DerObjectIdentifier oid = algorithmIdentifier.Algorithm;
        algorithm = new Oid(oid.Id);
        return true;
    }
    /// <summary>
    /// Attempts to extract public key parameters such as algorithm OID and key size from a PKCS#10 certification request.
    /// </summary>
    /// <param name="this">The certification request.</param>
    /// <param name="algorithm">When this method returns, contains the public key parameters if successfully retrieved; otherwise, null.</param>
    /// <returns><c>true</c> if public key parameters were successfully retrieved; otherwise, <c>false</c>.</returns>
    public static bool TryGetPublicKeyParameters(
        [NotNullWhen(true)] this Pkcs10CertificationRequest? @this,
        [NotNullWhen(true)] out PublicKeyParams? algorithm)
    {
        if (@this is null)
        {
            algorithm = null;
            return false;
        }

        AsymmetricKeyParameter key = @this.GetPublicKey();

        if (key is DsaKeyParameters dsa)
        {
            algorithm = new PublicKeyParams(new Oid(X9ObjectIdentifiers.IdDsa.Id), dsa.Parameters.P.BitLength);
            return true;
        }
        else if (key is RsaKeyParameters rsa)
        {
            algorithm = new PublicKeyParams(new Oid(PkcsObjectIdentifiers.RsaEncryption.Id), rsa.Modulus.BitLength);
            return true;
        }
        else if (key is ECPublicKeyParameters ec)
        {
            algorithm = new PublicKeyParams(new Oid(ec.PublicKeyParamSet.Id), ec.Parameters.Curve.FieldSize);
            return true;
        }
        else if (key is Ed25519PublicKeyParameters)
        {
            algorithm = new PublicKeyParams(new Oid(EdECObjectIdentifiers.id_Ed25519.Id), Ed25519.PublicKeySize);
            return true;
        }
        else if (key is Ed448PublicKeyParameters)
        {
            algorithm = new PublicKeyParams(new Oid(EdECObjectIdentifiers.id_Ed448.Id), Ed448.PublicKeySize);
            return true;
        }

        algorithm = null;
        return false;
    }
    /// <summary>
    /// Attempts to extract Subject Alternative Names (SAN) from a PKCS#10 certification request.
    /// </summary>
    /// <param name="this">The PKCS#10 certification request.</param>
    /// <param name="subjectAltNames">When this method returns, contains an immutable array of parsed SANs if successful; otherwise, empty.</param>
    /// <returns>True if SANs were extracted; otherwise, false.</returns>
    public static bool TryGetSubjectAltNames(
        [NotNullWhen(true)] this Pkcs10CertificationRequest? @this,
        out ImmutableArray<ISubjectAltName> subjectAltNames)
    {
        ImmutableArrayBuilder<ISubjectAltName> builder = [];
        if (@this is null)
        {
            subjectAltNames = builder.ToImmutable();
            return false;
        }

        CertificationRequestInfo certificationRequestInfo = @this.GetCertificationRequestInfo();
        Asn1Set attributes = certificationRequestInfo.Attributes;

        if (attributes.Count > 0)
        {
            DerSequence? pkcs9Extensions = attributes.OfType<DerSequence>()
                .FirstOrDefault(
                    static seq => seq.OfType<DerObjectIdentifier>().Any(
                        PkcsObjectIdentifiers.Pkcs9AtExtensionRequest.Equals));
            if (pkcs9Extensions is not null)
            {
                DerSet? extensions = pkcs9Extensions.OfType<DerSet>().FirstOrDefault();
                if (extensions is not null)
                {
                    DerOctetString? octets = extensions
                        .OfType<DerSequence>()
                        .First()
                        .GetAsn1ObjectById<DerOctetString>(X509Extensions.SubjectAlternativeName);

                    if (octets is not null)
                    {
                        Asn1Object? parsedObject = Asn1Object.FromByteArray(octets.GetOctets());
                        GeneralName[] generalNames = GeneralNames.GetInstance(parsedObject).GetNames();

                        foreach (GeneralName item in generalNames)
                        {
                            builder.Add(SubjectAltNameAdapter.Default.Adapt(item));
                        }
                    }
                }
            }
        }

        subjectAltNames = builder.ToImmutable();
        return true;
    }

    private static AsymmetricAlgorithm ToDotNetPrivateKey(this AsymmetricCipherKeyPair @this)
    {
        switch (@this.Private)
        {
            case RsaPrivateCrtKeyParameters privateKey:
            {
                RSAParameters rsaParams = DotNetUtilities.ToRSAParameters(privateKey);
                RSA rsa = RSA.Create();
                rsa.ImportParameters(rsaParams);

                return rsa;
            }

            case ECPrivateKeyParameters ecPrivate:
            {
                string oid = ecPrivate.PublicKeyParamSet.Id;
                if (oid != ECCurve.NamedCurves.nistP256.Oid.Value &&    // secp256r1 / P-256
                    oid != ECCurve.NamedCurves.nistP384.Oid.Value &&    // secp384r1 / P-384
                    oid != ECCurve.NamedCurves.nistP521.Oid.Value)      // secp521r1 / P-521
                {
                    throw new NotSupportedException($"Unsupported EC named curve with OID {oid}. " +
                        "Only secp256r1 (P-256), secp384r1 (P-384), and secp521r1 (P-521) are supported.");
                }

                PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(ecPrivate);
                byte[] pkcs8Bytes = privateKeyInfo.GetEncoded(Asn1Encodable.Der);

                ECDsa ecdsa = ECDsa.Create();
                // This method only supports the binary (BER/CER/DER) encoding of PrivateKeyInfo.
                // If the value is Base64-encoded, the caller must Base64-decode the contents before calling this method.
                // If the value is PEM-encoded, "ImportFromPem" should be used.
                ecdsa.ImportPkcs8PrivateKey(pkcs8Bytes, out _);

                return ecdsa;
            }
            default:
            {
                throw new NotSupportedException($"Unsupported algorithm specified {@this.GetType().FullName ?? @this.GetType().Name}. Only RSA and ECDsa keys are supported.");
            }
        }
    }

    private static AsymmetricCipherKeyPair ToBouncyCastlePrivateKey(this AsymmetricAlgorithm @this) => @this switch
    {
        RSA rsa => DotNetUtilities.GetRsaKeyPair(rsa),
        ECDsa ec => DotNetUtilities.GetECDsaKeyPair(ec),
        _ => throw new NotSupportedException(
            $"Unsupported algorithm specified {@this.GetType().FullName ?? @this.GetType().Name}. Only RSA and ECDsa keys are supported.")
    };

    /// <summary>
    /// Helper to retrieve an <see cref="Asn1Object"/> by OID from a <see cref="DerSequence"/> recursively.
    /// </summary>
    /// <typeparam name="T">The ASN.1 type to cast to.</typeparam>
    /// <param name="this">Sequence to search.</param>
    /// <param name="oid">Object Identifier to search for.</param>
    /// <returns>The ASN.1 object if found; otherwise, null.</returns>
    private static T? GetAsn1ObjectById<T>(
        this DerSequence @this, DerObjectIdentifier oid) where T : Asn1Object
    {
        if (@this.OfType<DerObjectIdentifier>().Any(oid.Equals))
        {
            return @this.OfType<T>().First();
        }

        foreach (DerSequence subSequence in @this.OfType<DerSequence>())
        {
            T? value = subSequence.GetAsn1ObjectById<T>(oid);
            if (value is not null)
            {
                return value;
            }
        }
        return null;
    }
}
