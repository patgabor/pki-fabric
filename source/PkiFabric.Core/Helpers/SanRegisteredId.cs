// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Cryptography;

using PkiFabric.Core.Diagnostics;

namespace PkiFabric.Core.Helpers;

public sealed class SanRegisteredId(Oid value) : ISubjectAltName
{
    [LogAsOid] public Oid Value { get; } = value;
}
