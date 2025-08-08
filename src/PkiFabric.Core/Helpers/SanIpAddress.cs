// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Net;

using Destructurama.Attributed;

namespace PkiFabric.Core.Helpers;

public sealed class SanIpAddress(IPAddress value) : ISubjectAltName
{
    [LogAsScalar] public IPAddress Value { get; } = value;
}
