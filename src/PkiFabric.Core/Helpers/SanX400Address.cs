// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Represents a Subject Alternative Name (SAN) X.400 address.
/// </summary>
/// <remarks>
/// The X.400 address is represented as an immutable dictionary of tagged fields,
/// where each key is an integer tag and the corresponding value is a string.
/// This format corresponds to the structure used in the SAN extension of a certificate to encode X.400 addresses.
/// </remarks>
public sealed class SanX400Address(ImmutableDictionary<int, string> taggedFields) : ISubjectAltName
{
    /// <summary>
    /// Gets the collection of tagged fields that make up the X.400 address,
    /// with each field identified by an integer tag and its associated string value.
    /// </summary>
    public ImmutableDictionary<int, string> TaggedFields { get; } = taggedFields;
}
