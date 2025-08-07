using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This class enriches log events with the full user name, including the domain if available.
/// </summary>
internal sealed class UserNameEnricher : ILogEventEnricher
{
    private const string PropertyName = "UserName";

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        string userDomainName = Environment.UserDomainName;
        string userName = Environment.UserName;

        string fullUserName = userDomainName switch
        {
            null or not null when userDomainName == string.Empty => userName,
            _ => $@"{userDomainName}\{userName}"
        };

        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, fullUserName);
        logEvent.AddPropertyIfAbsent(property);
    }
}
