// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.


using System.Text;

using Org.BouncyCastle.Asn1;

using PkiFabric.Core.Cryptography;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Adapter for encoding/decoding MS Security Object SIDs (AD Object SIDs) 
/// as ASN.1 OtherName structures conforming to MS-WCCE specification.
/// See https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/e563cff8-1af6-4e6f-a655-7571ca482e71
/// </summary>
public sealed class MsSecurityObjectSidAdapter :
    IAdapter<byte[], MsSecurityObjectSid>,
    IAdapter<MsSecurityObjectSid, byte[]>
{
    /// <summary>
    /// OID for the NTDS Object SID.
    /// </summary>
    private const string NtdsObjectSid = "1.3.6.1.4.1.311.25.2.1";

    private static readonly Encoding s_encoding = Encoding.ASCII;
    private static readonly DerObjectIdentifier s_oidNtdsObject = new(NtdsObjectSid);

    /// <summary>
    /// Gets a default instance of <see cref="MsSecurityObjectSidAdapter"/>.
    /// </summary>
    public static MsSecurityObjectSidAdapter Default { get; } = new();

    /// <summary>
    /// Parses ASN.1 encoded OtherName wrapping a Security Identifier (SID) from input bytes.
    /// Validates structure and OID.
    /// </summary>
    /// <param name="source">The DER-encoded ASN.1 OtherName byte array.</param>
    /// <returns>An instance of <see cref="MsSecurityObjectSid"/>.</returns>
    /// <exception cref="FormatException">When the ASN.1 structure is invalid or inconsistent.</exception>
    public MsSecurityObjectSid Adapt(byte[] source)
    {
        using Asn1InputStream asn1Stream = new(source);
        if (!(asn1Stream.ReadObject() is Asn1Sequence { Count: 1 } root))
        {
            throw new FormatException("Invalid ASN.1 structure for MsSecurityObjectSid.");
        }
        if (!(root[0] is DerTaggedObject { TagNo: 0 } container))
        {
            throw new FormatException("Invalid ASN.1 structure for MsSecurityObjectSid.");
        }
        if (!(container.GetBaseObject() is DerSequence { Count: 2 } otherName))
        {
            throw new FormatException("Invalid ASN.1 structure for MsSecurityObjectSid.");
        }
        if (!(otherName[0].ToAsn1Object() is DerObjectIdentifier identifier && identifier.Equals(s_oidNtdsObject)))
        {
            throw new FormatException($"Invalid OID for MsSecurityObjectSid: expected {s_oidNtdsObject}.");
        }
        if (!(otherName[1].ToAsn1Object() is DerTaggedObject { TagNo: 0 } taggedOctet))
        {
            throw new FormatException("Invalid ASN.1 structure for MsSecurityObjectSid.");
        }
        if (taggedOctet.GetBaseObject() is not DerOctetString octets)
        {
            throw new FormatException("Invalid ASN.1 structure for MsSecurityObjectSid.");
        }

        string sid = s_encoding.GetString(octets.GetOctets());

        return new MsSecurityObjectSid(sid);
    }

    /// <summary>
    /// Encodes an <see cref="MsSecurityObjectSid"/> instance into the ASN.1 DER encoded OtherName structure.
    /// </summary>
    /// <param name="source">The source SID instance.</param>
    /// <returns>DER-encoded byte array of the OtherName wrapping the SID.</returns>
    public byte[] Adapt(MsSecurityObjectSid source)
    {
        string sid = source.ToString();
        byte[] bytes = s_encoding.GetBytes(sid);

        DerSequence otherNameSequence = new(
            s_oidNtdsObject,
            new DerTaggedObject(true, tagNo: 0, new DerOctetString(bytes))
        );
        var rootTagged = new DerTaggedObject(true, tagNo: 0, obj: otherNameSequence);
        DerSequence root = new(rootTagged);

        byte[] extension = root.GetDerEncoded();

        return extension;
    }
}

