using System.Net.Mail;

using Destructurama.Attributed;

namespace PkiFabric.Core.Helpers;

public sealed class SanRfc822Name(MailAddress value) : ISubjectAltName
{
    [LogAsScalar] public MailAddress Value { get; } = value;
}
