using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using PkiFabric.Core.Helpers;
using static System.Security.Cryptography.X509Certificates.DSACertificateExtensions;
using static System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions;
using static System.Security.Cryptography.X509Certificates.RSACertificateExtensions;

using BcX509 = Org.BouncyCastle.X509;

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

            PemReader pemReader;
            if (password is null)
            {
                pemReader = new(reader);
            }
            else
            {
                pemReader = new(reader, new PasswordProxy(password));
            }

            privateKey = pemReader.ReadObject() as AsymmetricCipherKeyPair;
            return privateKey is not null;
        }
        catch (Exception x) when (x is PasswordException or PemException or IOException)
        {
            privateKey = null;
            return false;
        }
    }
}
