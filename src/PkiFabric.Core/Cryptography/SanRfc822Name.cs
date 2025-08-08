// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Net.Mail;

using Destructurama.Attributed;

namespace PkiFabric.Core.Cryptography;

/// <summary>
/// Represents a Subject Alternative Name (SAN) RFC 822 name, typically an email address.
/// </summary>
/// <remarks>
/// The RFC 822 name corresponds to an email address as specified in the SAN extension of a certificate.
/// The value is represented using the <see cref="MailAddress"/> class for proper email address semantics.
/// </remarks>
public sealed class SanRfc822Name(MailAddress value) : ISubjectAltName
{
    /// <summary>
    /// Gets the email address representing the RFC 822 name in the SAN extension.
    /// </summary>
    [LogAsScalar]
    public MailAddress Value { get; } = value;
}
