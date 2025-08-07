// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Diagnostics.CodeAnalysis;

using Destructurama.Attributed;

using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

using Oid = System.Security.Cryptography.Oid;

/// <summary>
/// Attribute to control how <see cref="Oid"/> values are logged with Serilog.
/// When applied to a class or property, it ensures that the OID value is logged as a scalar string.
/// Implements <see cref="ITypeDestructuringAttribute"/>, <see cref="IPropertyDestructuringAttribute"/>, and <see cref="ILogEventPropertyValueFactory"/>.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Property)]
public sealed class LogAsOidAttribute : Attribute, ITypeDestructuringAttribute, IPropertyDestructuringAttribute, ILogEventPropertyValueFactory
{
    /// <inheritdoc/>
    public LogEventPropertyValue CreateLogEventPropertyValue(object? value, ILogEventPropertyValueFactory propertyValueFactory)
        => CreatePropertyValue(value);

    /// <inheritdoc/>
    public LogEventPropertyValue CreatePropertyValue(object? value, bool destructureObjects = false)
        => value switch { Oid { Value: not null } oid => new ScalarValue(oid.Value), _ => ScalarValue.Null };

    /// <inheritdoc/>
    public bool TryCreateLogEventProperty(string name, object? value, ILogEventPropertyValueFactory propertyValueFactory, [NotNullWhen(true)] out LogEventProperty? property)
    {
        property = new(name, CreatePropertyValue(value));
        return true;
    }
}
