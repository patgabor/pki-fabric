// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Buffers.Text;
using System.Globalization;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using CommunityToolkit.Diagnostics;

using FluentValidation;

using PkiFabric.Core.Helpers;

namespace PkiFabric.Core.Extensions;

public static class FluentValidationExtensions
{
    public static IRuleBuilderOptions<T, string> BeAValidX500DistinguishedName<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("X500DistinguishedName cannot be empty.")
            .Must(static data =>
            {
                try
                {
                    _ = new X500DistinguishedName(data);
                    return true;
                }
                catch
                {
                    return false;
                }
            }).WithMessage(static (root, data) => $"Invalid X500DistinguishedName: \"{data}\".");
    }

    public static IRuleBuilderOptions<T, string> BeAValidEmail<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("Email address cannot be empty.")
            .Must(static data =>
                MailAddress.TryCreate(data, out MailAddress? result) &&
                result.Address.Equals(data, StringComparison.Ordinal))
            .WithMessage(static (root, data) => $"Invalid email address: \"{data}\".");
    }

    public static IRuleBuilderOptions<T, string> BeAValidPasword<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("Password cannot be empty.")
            .Must(static (root, data, context) =>
            {
                DefaultPasswordEntropyHelper helper = new();
                double entropy = helper.ComputeEntropy(data);
                PasswordSecurityLevel strength = helper.EvaluateStrength(entropy);

                context.MessageFormatter.AppendArgument("Strength", strength.ToString());
                context.MessageFormatter.AppendArgument("Entropy", Math.Round(entropy, 2).ToString(NumberFormatInfo.InvariantInfo));

                return strength >= PasswordSecurityLevel.Good;
            })
            .WithMessage(static (root) => "Weak password, strength: \"{Strength}\", entropy: \"{Entropy}\".");
    }

    public static IRuleBuilderOptions<T, string> BeAValidUrl<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("URL cannot be empty.")
            .Must(static data =>
                Uri.TryCreate(data, UriKind.Absolute, out Uri? uri) &&
                (uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.Ordinal) ||
                uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.Ordinal)))
            .WithMessage(static (root, data) => $"Invalid URL: \"{data}\".");
    }

    public static IRuleBuilderOptions<T, int> BeAValidPortNumber<T>(this IRuleBuilder<T, int> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .InclusiveBetween(IPEndPoint.MinPort, IPEndPoint.MaxPort)
            .WithMessage(static (root, data) => $"Invalid port number: \"{data.ToString(NumberFormatInfo.InvariantInfo)}\".");
    }

    public static IRuleBuilderOptions<T, string> BeAValidIpAddress<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        return ruleBuilder
            .NotEmpty().WithMessage("IP address cannot be empty.")
            .Must(static data =>
                IPAddress.TryParse(data, out IPAddress? ip) && ip is { AddressFamily: AddressFamily.InterNetwork or AddressFamily.InterNetworkV6 })
            .WithMessage(static (root, data) => $"Invalid IP address: \"{data}\".");
    }

    public static IRuleBuilderOptions<T, string> BeAValidBase64<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("Base64 data cannot be empty.")
            .Must(static data => Base64.IsValid(data))
            .WithMessage(static (root, data) => "Invalid base64 data.");
        // do not include the invalid data in the message,
        // as it may potentially be a sensitive value like private key
    }

    public static IRuleBuilderOptions<T, string> BeAValidCountryCode<T>(this IRuleBuilder<T, string> ruleBuilder)
    {
        Guard.IsNotNull(ruleBuilder);

        return ruleBuilder
            .NotEmpty().WithMessage("Country code cannot be empty.")
            .Must(static data => new DefaultCountryCodeHelper().Codes.Contains(data, StringComparer.Ordinal))
            .WithMessage(static (root, data) => $"Invalid ISO 3166-1 alpha-2 country code: \"{data}\".");
    }
}
