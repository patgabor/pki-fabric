// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This enricher adds the total memory usage of the application to the log events.
/// </summary>
public sealed class MemoryUsageEnricher : ILogEventEnricher
{
    private const string PropertyName = "MemoryUsage";
    /// <inheritdoc/>
    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        long memoryUsage = GC.GetTotalMemory(false);

        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, memoryUsage);
        logEvent.AddPropertyIfAbsent(property);
    }
}
