using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This class enriches log events with the machine name where the application is running.
/// </summary>
internal sealed class MachineNameEnricher : ILogEventEnricher
{
    private const string PropertyName = "MachineName";
    private static readonly string s_machineName = Environment.MachineName;

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, s_machineName);
        logEvent.AddPropertyIfAbsent(property);
    }
}