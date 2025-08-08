// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

public sealed class SanDnsName(string value) : ISubjectAltName
{
    public string Value { get; } = value;
}
