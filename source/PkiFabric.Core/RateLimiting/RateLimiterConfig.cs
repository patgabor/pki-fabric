// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.ComponentModel.DataAnnotations;

namespace PkiFabric.Core.RateLimiting;

/// <summary>
/// Configuration options for the Rate Limiter feature.
/// This class defines the settings to control the allowed number of requests per time interval.
/// It is usually bound to the "RateLimiter" configuration section.
/// </summary>
public sealed class RateLimiterConfig
{
    /// <summary>
    /// Configuration section name used for binding in appsettings.json or other configuration sources.
    /// </summary>
    public const string SectionName = "RateLimiter";
    /// <summary>
    /// Maximum number of allowed requests per hour.
    /// Must be a positive integer.
    /// Default value is 1000, override in configuration if needed.
    /// </summary>
    [Range(1, int.MaxValue, ErrorMessage = "Value for {0} must be between {1} and {2}.")]
    public int MaxRequestsPerHour { get; set; } = 1000; // Default value, can be overridden in configuration
    /// <summary>
    /// Maximum number of allowed requests per minute.
    /// Must be a positive integer.
    /// Default value is 100, override in configuration if needed.
    /// </summary>
    [Range(1, int.MaxValue, ErrorMessage = "Value for {0} must be between {1} and {2}.")]
    public int MaxRequestsPerMinute { get; set; } = 100; // Default value, can be overridden in configuration
}
