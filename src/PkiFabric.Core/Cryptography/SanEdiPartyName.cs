// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Subject Alternative Name (SAN) EDI (Electronic Data Interchange) party name.
/// </summary>
/// <remarks>
/// The EDI party name can include an optional name assigner that identifies who assigned the party name.
/// Typical usage is in certificates that require encoding party names in the SAN extension.
/// </remarks>
public sealed class SanEdiPartyName(string partyName, string? nameAssigner = null) : ISubjectAltName
{
    /// <summary>
    /// Gets the optional name assigner that identifies the naming authority for the party name.
    /// </summary>
    public string? NameAssigner { get; } = nameAssigner;
    /// <summary>
    /// Gets the EDI party name.
    /// </summary>
    public string PartyName { get; } = partyName;
}
