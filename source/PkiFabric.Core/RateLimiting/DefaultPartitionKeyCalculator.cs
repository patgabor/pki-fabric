// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Claims;

using CommunityToolkit.Diagnostics;

using Microsoft.AspNetCore.Http;

namespace PkiFabric.Core.RateLimiting;

/// <summary>
/// Calculates the partition key based on the <see cref="ClaimTypes.Name"/> the caller has.
/// </summary>
public sealed class DefaultPartitionKeyCalculator : IPartitionKeyCalculator
{
    private const string DefaultPartitionKey = "Unknown";

    /// <inheritdoc />
    public string CalculatePartitionKey(HttpContext context)
    {
        Guard.IsNotNull(context);

        ClaimsPrincipal user = context.User;
        Claim? claim = user.Claims.FirstOrDefault(
            static claim => string.Equals(claim.Type, ClaimTypes.Name, StringComparison.Ordinal));

        string partitionKey = claim?.Value ?? DefaultPartitionKey;

        return partitionKey;
    }
}
