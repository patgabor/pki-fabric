// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Globalization;
using System.Threading.RateLimiting;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;

namespace PkiFabric.Core.RateLimiting;

/// <summary>
/// An abstract class which is used to represent a RateLimiter with key type of <see cref="string"/> policy.
/// </summary>
public abstract class RateLimiterPolicyBase(IPartitionKeyCalculator partitionKeyCalculator) : IRateLimiterPolicy<string>
{
    private readonly IPartitionKeyCalculator _partitionKeyCalculator = partitionKeyCalculator;

    /// <inheritdoc/>
    public virtual Func<OnRejectedContext, CancellationToken, ValueTask> OnRejected => async (ctx, ct) =>
    {
        string partitionKey = _partitionKeyCalculator.CalculatePartitionKey(ctx.HttpContext);

        ctx.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;

        if (ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out TimeSpan retryAfter))
        {
            string ms = ((long)retryAfter.TotalMilliseconds).ToString(NumberFormatInfo.InvariantInfo);
            ctx.HttpContext.Response.Headers.RetryAfter = ms;

            await ctx.HttpContext.Response.WriteAsync(
                $"Rate limit exceeded for your partition '{partitionKey}'. Retry after {ms} ms.", ct);
        }
        else
        {
            await ctx.HttpContext.Response.WriteAsync(
                $"Rate limit exceeded for your partition '{partitionKey}'.", ct);
        }
    };

    /// <inheritdoc/>
    public abstract RateLimitPartition<string> GetPartition(HttpContext httpContext);
}
