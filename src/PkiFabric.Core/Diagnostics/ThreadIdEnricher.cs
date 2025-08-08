// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// // This class enriches log events with the current managed thread ID,
/// which can be useful for debugging and tracing issues related to multithreading in applications.
/// </summary>
internal sealed class ThreadIdEnricher : ILogEventEnricher
{
    private const string PropertyName = "ThreadId";

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        LogEventProperty prop = propertyFactory.CreateProperty(PropertyName, Environment.CurrentManagedThreadId);

        logEvent.AddPropertyIfAbsent(prop);
    }
}
