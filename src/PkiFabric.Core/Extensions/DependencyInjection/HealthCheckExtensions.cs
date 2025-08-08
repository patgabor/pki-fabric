// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using CommunityToolkit.Diagnostics;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace PkiFabric.Core.Extensions.DependencyInjection;

/// <summary>
/// Provides extension methods for registering and mapping health check endpoints 
/// and health checks in the application.
/// </summary>
public static class HealthCheckExtensions
{
    private static class HealthCheckKinds
    {
        public const string Startup = "startup";
        public const string Readiness = "readiness";
    }

    private static class HealthCheckLabels
    {
        public const string Lifecycle = "lifecycle";
        public const string CpuUsage = "cpu";
        public const string MemoryUsage = "memory";
    }

    /// <summary>
    /// Maps health check endpoints for readiness and startup checks to the specified <paramref name="this"/> route builder.
    /// The endpoints are exposed on the given <paramref name="managementPort"/> (default: "*:8080").
    /// </summary>
    /// <param name="this">The endpoint route builder to map health check endpoints to.</param>
    /// <param name="managementPort">The host and port to require for the health check endpoints (default: "*:8080").</param>
    /// <returns>The <see cref="IEndpointRouteBuilder"/> for chaining.</returns>
    public static IEndpointRouteBuilder MapHealthCheckEndpoints(this IEndpointRouteBuilder @this,
        string managementPort = "*:8080")
    {
        Guard.IsNotNull(@this);
        Guard.IsNotNullOrWhiteSpace(managementPort);

        _ = @this.MapHealthChecks("/healthz/ready", new HealthCheckOptions
        {
            Predicate = static hc => hc.Tags.Contains(HealthCheckKinds.Readiness)
        }).RequireHost(managementPort);

        _ = @this.MapHealthChecks("/healthz/startup", new HealthCheckOptions
        {
            Predicate = static hc => hc.Tags.Contains(HealthCheckKinds.Startup)
        }).RequireHost(managementPort);

        return @this;
    }

    /// <summary>
    /// Adds health checks for application startup lifecycle.
    /// </summary>
    /// <param name="this">The service collection to add health checks to.</param>
    /// <returns>The <see cref="IHealthChecksBuilder"/> for chaining.</returns>
    public static IHealthChecksBuilder AddStartupHealthChecks(this IServiceCollection @this)
    {
        Guard.IsNotNull(@this);

        return @this.AddHealthChecks()
            .AddApplicationLifecycleHealthCheck(
                HealthCheckKinds.Readiness, HealthCheckKinds.Startup, HealthCheckLabels.Lifecycle);
    }

    /// <summary>
    /// Adds health checks for core system resources such as CPU and memory utilization.
    /// Allows configuration of degraded and unhealthy thresholds for CPU and memory usage.
    /// </summary>
    /// <param name="this">The service collection to add health checks to.</param>
    /// <param name="degradedCpuPercentage">The CPU usage percentage at which the health check reports degraded status (default: 80).</param>
    /// <param name="unhealthyCpuPercentage">The CPU usage percentage at which the health check reports unhealthy status (default: 90).</param>
    /// <param name="degradedMemoryPercentage">The memory usage percentage at which the health check reports degraded status (default: 80).</param>
    /// <param name="unhealthyMemoryPercentage">The memory usage percentage at which the health check reports unhealthy status (default: 90).</param>
    /// <returns>The <see cref="IHealthChecksBuilder"/> for chaining.</returns>
    public static IHealthChecksBuilder AddCoreHealthChecks(this IServiceCollection @this,
        double degradedCpuPercentage = 80,
        double unhealthyCpuPercentage = 90,
        double degradedMemoryPercentage = 80,
        double unhealthyMemoryPercentage = 90)
    {
        Guard.IsNotNull(@this);

        Guard.IsBetweenOrEqualTo(degradedCpuPercentage, 0, 100);
        Guard.IsBetweenOrEqualTo(unhealthyCpuPercentage, degradedCpuPercentage, 100);
        Guard.IsBetweenOrEqualTo(degradedMemoryPercentage, 0, 100);
        Guard.IsBetweenOrEqualTo(unhealthyMemoryPercentage, degradedMemoryPercentage, 100);

        return @this.AddHealthChecks()
            .AddResourceUtilizationHealthCheck(
                resources =>
                {
                    resources.CpuThresholds = new ResourceUsageThresholds
                    {
                        DegradedUtilizationPercentage = degradedCpuPercentage,
                        UnhealthyUtilizationPercentage = unhealthyCpuPercentage
                    };
                    resources.MemoryThresholds = new ResourceUsageThresholds
                    {
                        DegradedUtilizationPercentage = degradedMemoryPercentage,
                        UnhealthyUtilizationPercentage = unhealthyMemoryPercentage
                    };
                }, HealthCheckKinds.Readiness, HealthCheckLabels.CpuUsage, HealthCheckLabels.MemoryUsage);
    }
}
