using Microsoft.AspNetCore.Http;
using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This enricher adds a correlation ID to log events, which is useful for tracing requests across distributed systems.
/// </summary>
internal sealed class CorrelationIdEnricher(IHttpContextAccessor httpContextAccessor) : ILogEventEnricher
{
    private const string PropertyName = "CorrelationId";

    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    public CorrelationIdEnricher() : this(new HttpContextAccessor()) { }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        HttpContext? httpContext = _httpContextAccessor.HttpContext;
        if (httpContext is null)
        {
            return;
        }

        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, httpContext.TraceIdentifier);
        logEvent.AddPropertyIfAbsent(property);
    }
}
