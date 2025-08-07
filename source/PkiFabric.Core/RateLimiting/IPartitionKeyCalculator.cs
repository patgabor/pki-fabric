// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Microsoft.AspNetCore.Http;

namespace PkiFabric.Core.RateLimiting;

/// <summary>
/// Calculates the partition key based on the provided key.
/// </summary>
public interface IPartitionKeyCalculator
{
    /// <summary>
    /// Calculates the partition key based on the provided key.
    /// </summary>
    /// <param name="context">The <see cref="HttpContent"/> to calculate the partition key for.</param>
    /// <returns>The calculated partition key.</returns>
    string CalculatePartitionKey(HttpContext context);
}
