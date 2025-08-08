// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Net.Mail;

using Destructurama.Attributed;

namespace PkiFabric.Core.Helpers;

public sealed class SanRfc822Name(MailAddress value) : ISubjectAltName
{
    [LogAsScalar] public MailAddress Value { get; } = value;
}
