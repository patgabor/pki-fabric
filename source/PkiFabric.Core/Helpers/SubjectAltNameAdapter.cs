using System.Net;
using System.Net.Mail;
using System.Security.Cryptography;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Converts various Subject Alternative Name (SAN) types to Bouncy Castle's <see cref="GeneralName"/>
/// </summary>
public sealed class SubjectAltNameAdapter :
    IAdapter<SanRegisteredId, GeneralName>,
    IAdapter<SanIpAddress, GeneralName>,
    IAdapter<SanUniformResourceIdentifier, GeneralName>,
    IAdapter<SanEdiPartyName, GeneralName>,
    IAdapter<SanDirectoryName, GeneralName>,
    IAdapter<SanX400Address, GeneralName>,
    IAdapter<SanDnsName, GeneralName>,
    IAdapter<SanRfc822Name, GeneralName>,
    IAdapter<SanOtherName, GeneralName>,
    IAdapter<GeneralName, ISubjectAltName>
{
    /// <inheritdoc/>
    public GeneralName Adapt(SanIpAddress source)
    {
        DerOctetString ipAddress = new(source.Value.GetAddressBytes());
        return new(GeneralName.IPAddress, ipAddress);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanRegisteredId source)
    {
        DerObjectIdentifier oid = new(source.Value.Value);
        return new(GeneralName.RegisteredID, oid);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanUniformResourceIdentifier source)
    {
        DerIA5String uri = new(source.Value);
        return new(GeneralName.UniformResourceIdentifier, uri);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanEdiPartyName source)
    {
        // The optional nameAssigner is encoded as EXPLICIT UTF8String.
        // The mandatory partyName is encoded as EXPLICIT UTF8String.
        // Both are wrapped in a SEQUENCE.
        List<Asn1Encodable> elements = [];
        if (!string.IsNullOrWhiteSpace(source.NameAssigner))
        {
            var nameAssignerUtf8 = new DerUtf8String(source.NameAssigner);
            var taggedNameAssigner = new DerTaggedObject(isExplicit: true, tagNo: 0, obj: nameAssignerUtf8);
            elements.Add(taggedNameAssigner);
        }
        var partyNameUtf8 = new DerUtf8String(source.PartyName);
        var taggedPartyName = new DerTaggedObject(isExplicit: true, tagNo: 1, obj: partyNameUtf8);
        elements.Add(taggedPartyName);
        var ediPartyNameSequence = new DerSequence(elements.ToArray());
        return new GeneralName(GeneralName.EdiPartyName, ediPartyNameSequence);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanDirectoryName source)
    {
        X509Name x509Name = new(source.DistinguishedName);
        return new(GeneralName.DirectoryName, x509Name);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanX400Address source)
    {
        List<Asn1Encodable> asn1Elements = [];
        foreach (KeyValuePair<int, string> element in source.TaggedFields)
        {
            // Encode each value as an explicit UTF8String tagged with the tagNo
            DerUtf8String utf8String = new(element.Value);
            DerTaggedObject taggedObject = new(true, tagNo: element.Key, obj: utf8String);
            asn1Elements.Add(taggedObject);
        }

        var sequence = new DerSequence(asn1Elements.ToArray());
        return new GeneralName(GeneralName.X400Address, sequence);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanDnsName source)
    {
        DerIA5String dns = new(source.Value);
        return new(GeneralName.DnsName, dns);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanRfc822Name source)
    {
        DerIA5String rfc822Name = new(source.Value.Address);
        return new(GeneralName.Rfc822Name, rfc822Name);
    }
    /// <inheritdoc/>
    public GeneralName Adapt(SanOtherName source)
    {
        DerObjectIdentifier oid = new(source.TypeId.Value);
        DerUtf8String str = new(source.Value);
        DerSequence sequence = new(oid, new DerTaggedObject(0, str));
        return new(GeneralName.OtherName, sequence);
    }
    /// <inheritdoc/>
    public ISubjectAltName Adapt(GeneralName source)
    {
        return source.TagNo switch
        {
            GeneralName.OtherName => DecodeOtherName(source),
            GeneralName.IPAddress => DecodeIpAddress(source),
            GeneralName.UniformResourceIdentifier => DecodeUniformResourceIdentifier(source),
            GeneralName.EdiPartyName => DecodeEdiPartyName(source),
            GeneralName.DirectoryName => DecodeDirectoryName(source),
            GeneralName.X400Address => DecodeX400Address(source),
            GeneralName.DnsName => DecodeDnsName(source),
            GeneralName.Rfc822Name => DecodeRfc822Name(source),
            GeneralName.RegisteredID => DecodeRegisteredId(source),
            _ => throw new NotSupportedException($"Unsupported SAN type: {source.TagNo}")
        };
    }

    private static SanRegisteredId DecodeRegisteredId(GeneralName source)
    {
        DerObjectIdentifier oid = DerObjectIdentifier.GetInstance(source.Name);
        return new SanRegisteredId(new Oid(oid.Id));
    }

    private static SanRfc822Name DecodeRfc822Name(GeneralName source)
    {
        DerIA5String rfc822Name = DerIA5String.GetInstance(source.Name);
        MailAddress mail = new(rfc822Name.GetString());
        return new SanRfc822Name(mail);
    }

    private static SanDnsName DecodeDnsName(GeneralName source)
    {
        DerIA5String dnsName = DerIA5String.GetInstance(source.Name);
        return new SanDnsName(dnsName.GetString());
    }

    private static SanX400Address DecodeX400Address(GeneralName source)
    {
        Asn1Sequence sequence = Asn1Sequence.GetInstance(source.Name);
        ImmutableDictionaryBuilder<int, string> fields = [];
        foreach (Asn1Encodable element in sequence)
        {
            if (element is not Asn1TaggedObject taggedObject)
                throw new NotSupportedException("All elements inside X400Address sequence must be tagged objects.");

            int tagNo = taggedObject.TagNo;
            Asn1TaggedObject contextTagged =
                Asn1TaggedObject.GetInstance(taggedObject, Asn1Tags.ContextSpecific, tagNo);

            Asn1Encodable explicitValue = contextTagged.GetExplicitBaseObject();

            string decodedValue = DecodeAsn1String(explicitValue);

            fields.Add(tagNo, decodedValue);
        }

        if (!fields.Any())
        {
            throw new InvalidOperationException("X400Address ASN.1 sequence contains no tagged fields.");
        }

        return new SanX400Address(fields.ToImmutable());
    }

    private static SanDirectoryName DecodeDirectoryName(GeneralName source)
    {
        X509Name x509Name = X509Name.GetInstance(source.Name);
        return new SanDirectoryName(x509Name.ToString(reverse: false, X509Name.RFC2253Symbols));
    }

    private static SanEdiPartyName DecodeEdiPartyName(GeneralName source)
    {
        EdiPartyName ediPartyName = EdiPartyName.GetInstance(source.Name);

        string? nameAssigner = null;
        if (ediPartyName.NameAssigner is not null)
        {
            nameAssigner = ediPartyName.NameAssigner.ToString();
        }

        string partyName = ediPartyName.PartyName.ToString()
            ?? throw new InvalidOperationException($"{nameof(ediPartyName.PartyName)} is missing.");

        return new SanEdiPartyName(partyName, nameAssigner);
    }

    private static SanUniformResourceIdentifier DecodeUniformResourceIdentifier(GeneralName source)
    {
        string uniformResourceIdentifier = DerIA5String.GetInstance(source.Name).GetString();
        return new SanUniformResourceIdentifier(uniformResourceIdentifier);
    }

    private static SanIpAddress DecodeIpAddress(GeneralName source)
    {
        Asn1Object octetString = source.Name.ToAsn1Object();
        byte[] bytes = Asn1OctetString.GetInstance(octetString).GetOctets();
        IPAddress ipAddress = new(bytes);
        return new SanIpAddress(ipAddress);
    }

    private static SanOtherName DecodeOtherName(GeneralName source)
    {
        OtherName otherName = OtherName.GetInstance(source.Name);
        DerObjectIdentifier typeId = otherName.TypeID;
        Asn1Encodable asn1Encodable = otherName.Value;
        Asn1Object innerObject = asn1Encodable.ToAsn1Object();
        string value = innerObject switch
        {
            DerUtf8String utf8String => utf8String.GetString(),
            DerPrintableString printableString => printableString.GetString(),
            DerIA5String ia5String => ia5String.GetString(),
            DerBmpString bmpString => bmpString.GetString(),
            DerT61String t61String => t61String.GetString(),
            _ => innerObject.ToString() ?? // For unknown types, fall back to ASN.1 encoding string form
                throw new NotSupportedException(
                    $"Unsupported SAN type: {source.TagNo} - {innerObject.GetType().Name}"),
        };
        return new SanOtherName(value, new Oid(typeId.Id));
    }

    private static string DecodeAsn1String(Asn1Encodable baseObject) => baseObject switch
    {
        DerUtf8String utf8 => utf8.GetString(),
        DerPrintableString printable => printable.GetString(),
        DerIA5String ia5 => ia5.GetString(),
        DerBmpString bmp => bmp.GetString(),
        DerT61String t61 => t61.GetString(),
        _ => baseObject.ToString() ??
            throw new NotSupportedException(
                $"Unsupported string value type {baseObject.GetType().Name}"),
    };
}
