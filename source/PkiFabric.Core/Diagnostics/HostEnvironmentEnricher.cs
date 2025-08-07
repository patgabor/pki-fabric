// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Microsoft.Extensions.Hosting;

using Serilog.Core;
using Serilog.Events;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// This enricher adds the host environment (e.g., Development, Staging, Production) to log events.
/// </summary>
internal sealed class HostEnvironmentEnricher : ILogEventEnricher
{
    private const string PropertyName = "HostEnvironment";
    private const string AspNetCore = "ASPNETCORE_ENVIRONMENT";
    private const string DotNet = "DOTNET_ENVIRONMENT";

    // Microsoft's Default is Production if no environment variable is set
    public static readonly string s_fallbackEnvironment = Environments.Production;

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        string? environmentName = Environment.GetEnvironmentVariable(AspNetCore);

        if (string.IsNullOrWhiteSpace(environmentName))
        {
            environmentName = Environment.GetEnvironmentVariable(DotNet);
        }

        if (string.IsNullOrWhiteSpace(environmentName))
        {
            environmentName = s_fallbackEnvironment;
        }

        LogEventProperty property = propertyFactory.CreateProperty(PropertyName, environmentName);
        logEvent.AddPropertyIfAbsent(property);
    }
}
