using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This class enriches log events with the current number of active threads in the thread pool,
/// which can be useful for monitoring and diagnosing performance issues related to threading in applications.
/// </summary>
internal sealed class ThreadCountEnricher : ILogEventEnricher
{
    private const string PropertyName = "ActiveThreadCount";

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        LogEventProperty prop = propertyFactory.CreateProperty(PropertyName, ThreadPool.ThreadCount);

        logEvent.AddPropertyIfAbsent(prop);
    }
}
