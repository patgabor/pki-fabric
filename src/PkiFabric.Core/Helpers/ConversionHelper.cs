// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Provides helper methods for converting between Base64, hexadecimal, and raw byte arrays.
/// </summary>
public sealed class ConversionHelper : IConversionHelper
{
    // Does not insert line breaks after every 76 characters in the string representation.
    private const Base64FormattingOptions NoLineBreak = Base64FormattingOptions.None;

    /// <inheritdoc />
    public byte[] FromBase64(string base64String) => Convert.FromBase64String(base64String);
    /// <inheritdoc />
    public string ToBase64(ReadOnlySpan<byte> bytes) => Convert.ToBase64String(bytes, NoLineBreak);
    /// <inheritdoc />
    public byte[] FromHex(ReadOnlySpan<char> hex) => Convert.FromHexString(hex);
    /// <inheritdoc />
    public string ToHex(ReadOnlySpan<byte> bytes) => Convert.ToHexString(bytes);
}
