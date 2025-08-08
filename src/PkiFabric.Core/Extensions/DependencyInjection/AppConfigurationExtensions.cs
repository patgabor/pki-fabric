// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Globalization;
using System.Reflection;

using CommunityToolkit.Diagnostics;

using Destructurama;

using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Diagnostics.ExceptionSummarization;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using PkiFabric.Core.Diagnostics;
using PkiFabric.Core.RateLimiting;

using Serilog;
using Serilog.Configuration;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace PkiFabric.Core.Extensions.DependencyInjection;

/// <summary>
/// Provides extension methods for registering and mapping appconfig in the application.
/// </summary>
public static class AppConfigurationExtensions
{
    private static Assembly WorkerAssembly => Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();

    /// <summary>
    /// Adds the default exception handler and problem details services to the application.
    /// </summary>
    public static IServiceCollection AddApplicationExceptionHandler(this IServiceCollection @this)
    {
        Guard.IsNotNull(@this);

        _ = @this.AddProblemDetails();
        _ = @this.AddExceptionHandler<DefaultExceptionHandler>();

        return @this;
    }

    /// <summary>
    /// Uses middleware for the default exception handler and problem details services.
    /// </summary>
    public static IApplicationBuilder UseApplicationExceptionHandler(this IApplicationBuilder @this)
    {
        Guard.IsNotNull(@this);

        _ = @this.UseExceptionHandler();
        _ = @this.UseStatusCodePages();

        return @this;
    }

    /// <summary>
    /// Uses the default logger middleware of the application.
    /// </summary>
    public static IApplicationBuilder UseApplicationLogging(this IApplicationBuilder @this)
    {
        Guard.IsNotNull(@this);

        return @this.UseSerilogRequestLogging();
    }

    /// <summary>
    /// Provides logging functionality for HTTP client requests, including start, stop, and failure events.
    /// </summary>
    public static IHttpClientBuilder UseApplicationLogging(this IHttpClientBuilder @this)
    {
        Guard.IsNotNull(@this);

        _ = @this.RemoveAllLoggers();

        _ = @this.Services.AddExceptionSummarizer(static builder => builder.AddHttpProvider());
        _ = @this.Services.AddResilienceEnricher();

        @this.Services.TryAddScoped<HttpClientLogger>();
        return @this.AddLogger<HttpClientLogger>(wrapHandlersPipeline: false);
    }

    private const string HoursPolicyName = "RateLimiter_Hours";
    private const string MinutesPolicyName = "RateLimiter_Minutes";

    /// <summary>
    /// Provides extension methods for registering rate limiting in the application.
    /// </summary>
    public static IHostBuilder AddApplicationRateLimiting(this IHostBuilder @this)
    {
        Guard.IsNotNull(@this);

        // Register the rate limiter configuration
        return @this.ConfigureServices(static (context, services) =>
        {
            IConfigurationSection section = context.Configuration.GetSection(RateLimiterConfig.SectionName);
            OptionsBuilder<RateLimiterConfig> optionsBuilder = services.AddOptionsWithValidateOnStart<RateLimiterConfig>();
            if (section.Exists())
            {
                _ = optionsBuilder.Bind(section).ValidateDataAnnotations();
            }

            _ = services.AddSingleton<IPartitionKeyCalculator, DefaultPartitionKeyCalculator>();

            _ = services.AddRateLimiter(static options =>
            {
                _ = options // Add rate limiting policies
                    .AddPolicy<string, HoursRateLimiterPolicy>(HoursPolicyName)
                    .AddPolicy<string, MinutesRateLimiterPolicy>(MinutesPolicyName);
            });
        });
    }

    /// <summary>
    /// Configures logging for the service, including Serilog and other logging providers.
    /// </summary>
    /// <param name="this">The host builder to configure logging for.</param>
    /// <returns>The configured <see cref="IHostBuilder"/> for chaining.</returns>
    public static IHostBuilder AddApplicationLogging(this IHostBuilder @this)
    {
        Guard.IsNotNull(@this);

        // Configure logging here, e.g., add console, debug, etc.
        _ = @this.ConfigureLogging(static logging => logging.ClearProviders());

        // Add logging services
        _ = @this.ConfigureServices(static (context, services) => services.AddHttpContextAccessor());

        // Add serilog as the logging provider
        return @this.UseSerilog(static (context, serilog) =>
        {
            _ = serilog.MinimumLevel.Verbose();
            _ = serilog.MinimumLevel.Override(nameof(System), LogEventLevel.Warning);
            _ = serilog.MinimumLevel.Override(nameof(Microsoft), LogEventLevel.Warning);
            _ = serilog.MinimumLevel.Override(nameof(Microsoft.AspNetCore), LogEventLevel.Warning);
            _ = serilog.MinimumLevel.Override(nameof(Microsoft.AspNetCore.Hosting), LogEventLevel.Warning);
            _ = serilog.MinimumLevel.Override(nameof(Microsoft.AspNetCore.Mvc), LogEventLevel.Warning);
            _ = serilog.MinimumLevel.Override(nameof(Microsoft.AspNetCore.Routing), LogEventLevel.Warning);

            // Destructurama: use attributes for structured logging
            _ = serilog.Destructure.UsingAttributes();

            _ = serilog.Enrich.FromLogContext();

            _ = serilog.Enrich.WithCorrelationId();
            _ = serilog.Enrich.WithClientIp();
            _ = serilog.Enrich.WithThreadCount();
            _ = serilog.Enrich.WithThreadId();
            _ = serilog.Enrich.WithAssemblyName();
            _ = serilog.Enrich.WithAssemblyVersion();
            _ = serilog.Enrich.WithMachineName();
            _ = serilog.Enrich.WithUserName();
            _ = serilog.Enrich.WithHostEnvironment();
            _ = serilog.Enrich.WithMemoryUsage();

            _ = serilog.WriteTo.Async(static serilog =>
            {
                const string Template = "[{Timestamp:HH:mm:ss.fff} {Level:u3}] {Message:lj}{NewLine}{Properties:j}{NewLine}{Exception}";
                _ = serilog.Console( // see more: https://github.com/serilog/serilog/wiki/Formatting-Output
                    outputTemplate: Template,
                    theme: AnsiConsoleTheme.Code,
                    formatProvider: CultureInfo.InvariantCulture);
            });
        });
    }

    /// <summary>
    /// Enriches Serilog log events with the current active thread count.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithThreadCount(this LoggerEnrichmentConfiguration @this)
        => @this.With<ThreadCountEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the current active thread Id.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithThreadId(this LoggerEnrichmentConfiguration @this)
        => @this.With<ThreadIdEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the current correlation ID from the HTTP context, if available.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithCorrelationId(this LoggerEnrichmentConfiguration @this)
        => @this.With<CorrelationIdEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the client IP address from the HTTP context, if available.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithClientIp(this LoggerEnrichmentConfiguration @this)
        => @this.With<ClientIpEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the assembly name of the entry or executing assembly.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithAssemblyName(this LoggerEnrichmentConfiguration @this)
    {
        const string FallbackName = "Unknown";
        const string Property = "AssemblyName";

        return @this.WithProperty(Property, WorkerAssembly.GetName().Name ?? FallbackName);
    }

    /// <summary>
    /// Enriches Serilog log events with the assembly version of the entry or executing assembly.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithAssemblyVersion(this LoggerEnrichmentConfiguration @this)
    {
        const string FallbackVersion = "Unknown";
        const int FieldCount = 3;
        const string Property = "AssemblyVersion";

        return @this.WithProperty(Property, WorkerAssembly.GetName().Version?.ToString(FieldCount) ?? FallbackVersion);
    }

    /// <summary>
    /// Enriches Serilog log events with the runtime environment.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithHostEnvironment(this LoggerEnrichmentConfiguration @this)
        => @this.With<HostEnvironmentEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the machine name.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithMachineName(this LoggerEnrichmentConfiguration @this)
        => @this.With<MachineNameEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the user name and domain.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithUserName(this LoggerEnrichmentConfiguration @this)
        => @this.With<UserNameEnricher>();

    /// <summary>
    /// Enriches Serilog log events with the allocated memory.
    /// </summary>
    /// <param name="this">The logger enrichment configuration.</param>
    /// <returns>The logger configuration for chaining.</returns>
    public static LoggerConfiguration WithMemoryUsage(this LoggerEnrichmentConfiguration @this)
        => @this.With<MemoryUsageEnricher>();

    /// <summary>
    /// Adds application settings from JSON files and environment variables to the host builder's configuration.
    /// </summary>
    /// <param name="this">The host builder to configure.</param>
    /// <param name="optionalJson">Whether the JSON configuration files are optional. Default is false.</param>
    /// <param name="reloadOnChangeJson">Whether to reload configuration when JSON files change. Default is false.</param>
    /// <param name="envVarPrefix">An optional prefix for environment variables to include.</param>
    /// <returns>The configured <see cref="IHostBuilder"/> for chaining.</returns>
    public static IHostBuilder AddApplicationSettings(this IHostBuilder @this, bool optionalJson = false, bool reloadOnChangeJson = false, string? envVarPrefix = null)
    {
        Guard.IsNotNull(@this);

        return @this.ConfigureAppConfiguration((context, config) =>
        {
            _ = config.SetBasePath(AppContext.BaseDirectory);
            _ = config.AddJsonFile("appsettings.json", optionalJson, reloadOnChangeJson);

            if (context.HostingEnvironment.IsDevelopment())
            {
                _ = config.AddJsonFile($"appsettings.{Environments.Development}.json", optionalJson, reloadOnChangeJson);
            }
            if (context.HostingEnvironment.IsStaging())
            {
                _ = config.AddJsonFile($"appsettings.{Environments.Staging}.json", optionalJson, reloadOnChangeJson);
            }
            if (context.HostingEnvironment.IsProduction())
            {
                _ = config.AddJsonFile($"appsettings.{Environments.Production}.json", optionalJson, reloadOnChangeJson);
            }

            // Add environment variables
            _ = config.AddEnvironmentVariables(envVarPrefix);
        });
    }
}
