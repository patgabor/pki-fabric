namespace PkiFabric.Core.Helpers;

public sealed class SanEdiPartyName(string partyName, string? nameAssigner = null) : ISubjectAltName
{
    public string? NameAssigner { get; } = nameAssigner;
    public string PartyName { get; } = partyName;
}
