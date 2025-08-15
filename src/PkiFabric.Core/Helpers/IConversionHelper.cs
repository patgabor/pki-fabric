// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Provides helper methods for converting between Base64, hexadecimal, and raw byte arrays.
/// </summary>
public interface IConversionHelper
{
    /// <summary>
    /// Converts a Base64-encoded string into its equivalent byte array.
    /// </summary>
    byte[] FromBase64(string base64String);
    /// <summary>
    /// Converts a hexadecimal string representation into its equivalent byte array of 8-bit unsigned integers.
    /// </summary>
    byte[] FromHex(ReadOnlySpan<char> hex);
    /// <summary>
    /// Converts a byte array into its equivalent Base64-encoded string.
    /// </summary>
    string ToBase64(ReadOnlySpan<byte> bytes);
    /// <summary>
    /// Converts a span of 8-bit unsigned integers to its equivalent string representation that is encoded with uppercase hex characters.
    /// </summary>
    string ToHex(ReadOnlySpan<byte> bytes);
}
