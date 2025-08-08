// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC.Rfc8032;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

using PkiFabric.Core.Cryptography;
using PkiFabric.Core.Helpers;

using BcX509 = Org.BouncyCastle.X509;
using Oid = System.Security.Cryptography.Oid;

namespace PkiFabric.Core.Extensions;

/// <summary>
/// Provides extension methods for parsing cryptographic data from PEM-encoded strings.
/// </summary>
/// <remarks>This class includes methods for parsing PEM-encoded strings into various cryptographic objects, such
/// as  PKCS#10 certification requests, X.509 certificates, public keys, and private keys. Each method follows  a
/// "TryParse" pattern, returning a boolean to indicate success or failure, and outputs the parsed object  if
/// successful.</remarks>
public static class CryptographyExtensions
{
    /// <summary>
    /// Attempts to parse a PEM-encoded string into a <see cref="Pkcs10CertificationRequest"/> object.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing a PKCS#10 certification request.</param>
    /// <param name="certificationRequest">When this method returns, contains the parsed <see cref="Pkcs10CertificationRequest"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a <see cref="Pkcs10CertificationRequest"/>; otherwise, <c>false</c>.</returns>
    public static bool TryParseToPkcs10([NotNullWhen(true)] this string? @this, [NotNullWhen(true)] out Pkcs10CertificationRequest? certificationRequest)
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
    /// Attempts to parse a PEM-encoded string into an X.509 <see cref="BcX509.X509Certificate"/> object.
    /// </summary>
    /// <param name="this">The PEM-encoded string representing an X.509 certificate.</param>
    /// <param name="certificate">When this method returns, contains the parsed <see cref="BcX509.X509Certificate"/> if parsing succeeded; otherwise, null.</param>
    /// <returns><c>true</c> if the string was successfully parsed into a certificate; otherwise, <c>false</c>.</returns>
    public static bool TryParseToCertificate([NotNullWhen(true)] this string? @this, [NotNullWhen(true)] out BcX509.X509Certificate? certificate)
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

            certificate = pemReader.ReadObject() as BcX509.X509Certificate;
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
    public static bool TryParseToPublicKey([NotNullWhen(true)] this string? @this, [NotNullWhen(true)] out AsymmetricKeyParameter? publicKey)
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
    public static bool TryParseToPrivateKey([NotNullWhen(true)] this string? @this, string? password, [NotNullWhen(true)] out AsymmetricCipherKeyPair? privateKey)
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

    public static bool TryGetSubject(
        [NotNullWhen(true)] this Pkcs10CertificationRequest? @this,
        out ImmutableDictionary<Oid, ImmutableArray<string>> subject)
    {
        ImmutableDictionaryBuilder<Oid, ImmutableArray<string>> builder =
            new(OidEqualityComparer.Default);

        if (@this is null)
        {
            subject = builder.ToImmutable();
            return false;
        }

        CertificationRequestInfo certificationRequestInfo = @this.GetCertificationRequestInfo();
        IList<DerObjectIdentifier> oids = certificationRequestInfo.Subject.GetOidList();

        foreach (DerObjectIdentifier oid in oids)
        {
            IList<string> values = certificationRequestInfo.Subject.GetValueList(oid);
            builder.Add(new Oid(oid.Id), [.. values]);
        }

        subject = builder.ToImmutable();
        return true;
    }

    public static bool TryGetSubjectAlgorithm(
        [NotNullWhen(true)] this Pkcs10CertificationRequest? @this,
        [NotNullWhen(true)] out Oid? algorithm)
    {
        if (@this is null)
        {
            algorithm = null;
            return false;
        }

        CertificationRequestInfo certificationRequestInfo = @this.GetCertificationRequestInfo();
        SubjectPublicKeyInfo subjectPublicKeyInfo = certificationRequestInfo.SubjectPublicKeyInfo;
        AlgorithmIdentifier algorithmIdentifier = subjectPublicKeyInfo.Algorithm;
        DerObjectIdentifier oid = algorithmIdentifier.Algorithm;

        algorithm = new Oid(oid.Id);
        return true;
    }

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
