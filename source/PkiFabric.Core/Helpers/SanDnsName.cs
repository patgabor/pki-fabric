namespace PkiFabric.Core.Helpers;

public sealed class SanDnsName(string value) : ISubjectAltName
{
    public string Value { get; } = value;
}
