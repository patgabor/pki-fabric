// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Threading.RateLimiting;

using CommunityToolkit.Diagnostics;

using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace PkiFabric.Core.RateLimiting;

/// <summary>
/// This class implements a rate limiter policy that allows a fixed number of requests per minute.
/// </summary>
public sealed class MinutesRateLimiterPolicy(IPartitionKeyCalculator partitionKeyCalculator, IOptions<RateLimiterConfig> options)
    : RateLimiterPolicyBase(partitionKeyCalculator)
{
    private const int QueueLimit = 0;
    private const QueueProcessingOrder ProcessingOrder = QueueProcessingOrder.OldestFirst;
    private static readonly TimeSpan s_window = TimeSpan.FromMinutes(1);

    private readonly IPartitionKeyCalculator _partitionKeyCalculator = partitionKeyCalculator;
    private readonly IOptions<RateLimiterConfig> _options = options;

    /// <iheritdoc />
    public override RateLimitPartition<string> GetPartition(HttpContext httpContext)
    {
        Guard.IsNotNull(httpContext);

        string partitionKey = _partitionKeyCalculator.CalculatePartitionKey(httpContext);

        return RateLimitPartition.GetFixedWindowLimiter(partitionKey, partition =>
        {
            RateLimiterConfig config = _options.Value;
            return new FixedWindowRateLimiterOptions
            {
                AutoReplenishment = true,
                Window = s_window,
                PermitLimit = config.MaxRequestsPerMinute,
                QueueProcessingOrder = ProcessingOrder,
                QueueLimit = QueueLimit, // Adjust as needed
            };
        });
    }
}
