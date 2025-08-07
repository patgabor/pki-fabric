using System.Net;

using Destructurama.Attributed;

namespace PkiFabric.Core.Helpers;

public sealed class SanIpAddress(IPAddress value) : ISubjectAltName
{
    [LogAsScalar] public IPAddress Value { get; } = value;
}
