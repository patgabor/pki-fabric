namespace PkiFabric.Core.Helpers;

public sealed class SanUniformResourceIdentifier(string value) : ISubjectAltName
{
    public string Value { get; } = value;
}
