using System.Security.Cryptography;

using PkiFabric.Core.Diagnostics;

namespace PkiFabric.Core.Helpers;

public sealed class SanOtherName(string value, Oid typeId) : ISubjectAltName
{
    public string Value { get; } = value;
    [LogAsOid] public Oid TypeId { get; } = typeId;
}
