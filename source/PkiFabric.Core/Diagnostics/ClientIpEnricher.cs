using Microsoft.AspNetCore.Http;
using Serilog.Core;
using Serilog.Events;
using System.Net;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This enricher adds a source IP address to log events, which is useful for tracing requests across distributed systems.
/// </summary>
internal sealed class ClientIpEnricher(IHttpContextAccessor httpContextAccessor) : ILogEventEnricher
{
    private const string PropertyName = "ClientIp";
    private static readonly IPAddress s_fallbackIpAddress = IPAddress.None;

    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public ClientIpEnricher() : this(new HttpContextAccessor()) { }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        HttpContext? httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return;
        }

        IPAddress clientIp = httpContext.Connection.RemoteIpAddress ?? s_fallbackIpAddress;

        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, clientIp.ToString());
        logEvent.AddPropertyIfAbsent(property);
    }
}
