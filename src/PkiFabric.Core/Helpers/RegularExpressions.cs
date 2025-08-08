// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Text.RegularExpressions;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Common safe, compiled, culture‑invariant regular expressions with short timeouts.
/// </summary>
internal static partial class RegularExpressions
{
    private const int ShortTimeout = 200;

    [GeneratedRegex(
        @"^S-(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])-(?:0|[1-9][0-9]{0,15})(?:-(?:0|[1-9][0-9]{0,9})){1,255}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        ShortTimeout)]
    internal static partial Regex Sid();

    [GeneratedRegex(
        @"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        matchTimeoutMilliseconds: ShortTimeout)]
    internal static partial Regex Email();

    [GeneratedRegex(
        @"^(https?:\/\/)?(www\.)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$",
        RegexOptions.CultureInvariant | RegexOptions.Compiled,
        matchTimeoutMilliseconds: ShortTimeout)]
    internal static partial Regex Url();

    [GeneratedRegex(
            @"^((25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.|$)){4}$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled,
            matchTimeoutMilliseconds: ShortTimeout)]
    internal static partial Regex Ipv4();

    [GeneratedRegex(
            @"^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(::1)|::)$",
            RegexOptions.CultureInvariant | RegexOptions.Compiled,
            matchTimeoutMilliseconds: ShortTimeout)]
    internal static partial Regex Ipv6();
}
