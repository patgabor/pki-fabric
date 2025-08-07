// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

public sealed class SanX400Address(ImmutableDictionary<int, string> taggedFields) : ISubjectAltName
{
    public ImmutableDictionary<int, string> TaggedFields { get; } = taggedFields;
}
