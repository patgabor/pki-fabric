// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

public sealed class SanEdiPartyName(string partyName, string? nameAssigner = null) : ISubjectAltName
{
    public string? NameAssigner { get; } = nameAssigner;
    public string PartyName { get; } = partyName;
}
