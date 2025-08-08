// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.


using System.Globalization;
using System.Text;

using CommunityToolkit.Diagnostics;

using PkiFabric.Core.Helpers;

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Windows/Active Directory Security Identifier (SID) 
/// in binary and canonical string form.
/// This is a fully managed, cross-platform implementation based on [MS-DTYP] SID format.
/// </summary>
public sealed class MsSecurityObjectSid : IEquatable<MsSecurityObjectSid>
{
    /// <summary>
    /// OID for the NTDS CA Security Extension.
    /// </summary>
    public const string NtdsCaSecurityExtensionOid = "1.3.6.1.4.1.311.25.2";

    /// <summary>
    /// OID for the NTDS Object SID.
    /// </summary>
    public const string NtdsObjectSidOid = "1.3.6.1.4.1.311.25.2.1";

    private readonly byte[] _sidBytes;

    /// <summary>
    /// Creates a SID instance from a canonical string (e.g., S-1-5-21-...).
    /// </summary>
    /// <param name="sidString">The SID text representation.</param>
    /// <exception cref="ArgumentNullException">If sidString is null or empty.</exception>
    /// <exception cref="FormatException">If sidString is not in a valid SID format.</exception>
    public MsSecurityObjectSid(string sidString)
    {
        Guard.IsNotNullOrWhiteSpace(sidString);

        _sidBytes = ParseSidString(sidString);
    }

    /// <summary>
    /// Creates a SID instance from a binary SID (as in LDAP objectSid attribute).
    /// </summary>
    /// <param name="sidBytes">Binary SID data in native Windows layout.</param>
    /// <exception cref="ArgumentNullException">If sidBytes is null.</exception>
    /// <exception cref="ArgumentException">If sidBytes are not valid SID bytes.</exception>
    public MsSecurityObjectSid(byte[] sidBytes)
    {
        Guard.IsNotEmpty(sidBytes);

        if (!IsValidBinarySid(sidBytes))
            throw new ArgumentException("Invalid SID binary format.", nameof(sidBytes));

        _sidBytes = (byte[])sidBytes.Clone(); // store own copy
    }

    /// <summary>
    /// Gets a copy of the binary SID.
    /// </summary>
    public byte[] GetBytes() => (byte[])_sidBytes.Clone();

    /// <summary>
    /// Returns the canonical S-R-I-... SID string representation.
    /// </summary>
    public override string ToString() => ToSidString(_sidBytes);

    /// <inheritdoc/>
    public bool Equals(MsSecurityObjectSid? other)
        => other is not null && _sidBytes.AsSpan().SequenceEqual(other._sidBytes);

    /// <inheritdoc/>
    public override bool Equals(object? obj)
        => Equals(obj as MsSecurityObjectSid);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        HashCode hash = new ();
        hash.AddBytes(_sidBytes);
        return hash.ToHashCode();
    }

    /// <summary>
    /// Equality operator for comparing two <see cref="MsSecurityObjectSid"/> instances.
    /// </summary>
    public static bool operator ==(MsSecurityObjectSid? left, MsSecurityObjectSid? right)
        => Equals(left, right);

    /// <summary>
    /// Equality operator for comparing two <see cref="MsSecurityObjectSid"/> instances.
    /// </summary>
    public static bool operator !=(MsSecurityObjectSid? left, MsSecurityObjectSid? right)
        => !Equals(left, right);

    private static bool IsValidBinarySid(byte[] data)
    {
        if (data.Length < 8)
        {
            return false;
        }

        byte subAuthCount = data[1];
        int expectedLength = 8 + subAuthCount * 4;
        return data.Length == expectedLength;
    }

    private static string ToSidString(byte[] data)
    {
        byte revision = data[0];
        byte subAuthCount = data[1];

        ulong identifierAuthority =
            ((ulong)data[2] << 40) |
            ((ulong)data[3] << 32) |
            ((ulong)data[4] << 24) |
            ((ulong)data[5] << 16) |
            ((ulong)data[6] << 8) |
            data[7];

        var sb = new StringBuilder();
        sb.Append("S-")
            .Append(revision)
            .Append('-')
            .Append(identifierAuthority);

        for (int i = 0; i < subAuthCount; i++)
        {
            int offset = 8 + i * 4;
            uint subAuth = (uint)(data[offset]
                | (data[offset + 1] << 8)
                | (data[offset + 2] << 16)
                | (data[offset + 3] << 24));
            sb.Append('-')
                .Append(subAuth);
        }

        return sb.ToString();
    }

    private static byte[] ParseSidString(string sidString)
    {
        if (!RegularExpressions.Sid().IsMatch(sidString))
        {
            throw new FormatException($"Invalid SID string format: {sidString}");
        }

        string[] parts = sidString.Split('-', StringSplitOptions.RemoveEmptyEntries);
        byte revision = byte.Parse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture);
        ulong authority = ulong.Parse(parts[2], NumberStyles.None, CultureInfo.InvariantCulture);

        int subAuthCount = parts.Length - 3;
        if (subAuthCount is < 0 or > 255)
        {
            throw new FormatException("Invalid number of sub-authorities in SID string.");
        }

        byte[] result = new byte[8 + (subAuthCount * 4)];
        result[0] = revision;
        result[1] = (byte)subAuthCount;

        // Authority is stored in 6 bytes big-endian
        result[2] = (byte)((authority >> 40) & 0xFF);
        result[3] = (byte)((authority >> 32) & 0xFF);
        result[4] = (byte)((authority >> 24) & 0xFF);
        result[5] = (byte)((authority >> 16) & 0xFF);
        result[6] = (byte)((authority >> 8) & 0xFF);
        result[7] = (byte)(authority & 0xFF);

        // Write subauthorities (little-endian)
        for (int i = 0; i < subAuthCount; i++)
        {
            uint subAuth = uint.Parse(parts[i + 3], NumberStyles.None, CultureInfo.InvariantCulture);
            int offset = 8 + i * 4;
            result[offset] = (byte)(subAuth & 0xFF);
            result[offset + 1] = (byte)((subAuth >> 8) & 0xFF);
            result[offset + 2] = (byte)((subAuth >> 16) & 0xFF);
            result[offset + 3] = (byte)((subAuth >> 24) & 0xFF);
        }

        return result;
    }
}

