using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

public sealed class SanX400Address(ImmutableDictionary<int, string> taggedFields) : ISubjectAltName
{
    public ImmutableDictionary<int, string> TaggedFields { get; } = taggedFields;
}
