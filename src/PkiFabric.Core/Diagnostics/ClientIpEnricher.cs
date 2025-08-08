// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Net;

using Microsoft.AspNetCore.Http;

using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This enricher adds a source IP address to log events, which is useful for tracing requests across distributed systems.
/// </summary>
public sealed class ClientIpEnricher(IHttpContextAccessor httpContextAccessor) : ILogEventEnricher
{
    private const string PropertyName = "ClientIp";
    private static readonly IPAddress s_fallbackIpAddress = IPAddress.None;

    private readonly IHttpContextAccessor _httpContextAccessor = httpContextAccessor;

    /// <summary>
    /// Ctor that initializes the enricher with a default <see cref="HttpContextAccessor"/>.
    /// </summary>
    public ClientIpEnricher() : this(new HttpContextAccessor()) { }

    /// <inheritdoc/>
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
