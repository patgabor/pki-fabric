// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Diagnostics;
using System.Globalization;

using FastEndpoints;

namespace PkiFabric.Auth;

/// <summary>
/// Logging processors that logs the request and response
/// </summary>
internal static class EndpointLogging
{
    /// <summary>
    /// It is a simple class that holds the common state for the
    /// global pre- and post-processors.
    /// </summary>
    [DebuggerDisplay($"{{{nameof(GetDebuggerDisplay)}(),nq}}")]
    public sealed class ContextState
    {
        private readonly Stopwatch _sw = Stopwatch.StartNew();

        /// <summary>
        /// Gets the total elapsed time measured by the current instance,
        /// in milliseconds.
        /// </summary>
        public long DurationMillis =>
            _sw.ElapsedMilliseconds;

        private string GetDebuggerDisplay() =>
            DurationMillis.ToString(NumberFormatInfo.InvariantInfo);
    }

    /// <summary>
    /// Logging processor that logs the request
    /// </summary>
    public sealed class PreProcessor : GlobalPreProcessor<ContextState>
    {
        /// <inheritdoc/>
        public override Task PreProcessAsync(IPreProcessorContext context, ContextState state, CancellationToken ct)
        {
            ILogger<PreProcessor> logger = context.HttpContext.Resolve<ILogger<PreProcessor>>();

            string request = context.Request?.GetType().Name ?? "Unknown";

            logger.LogInformation("Endpoint executing with request \"{Request}\".", request);

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// Logging processor that logs the request and response
    /// </summary>
    public sealed class PostProcessor : GlobalPostProcessor<ContextState>
    {
        /// <inheritdoc/>
        public override Task PostProcessAsync(IPostProcessorContext context, ContextState state, CancellationToken ct)
        {
            ILogger<PostProcessor> logger = context.HttpContext.Resolve<ILogger<PostProcessor>>();

            string request = context.Request?.GetType().Name ?? "Unknown";
            string response = context.Response?.GetType().Name ?? "Unknown";

            logger.LogInformation("Endpoint executed with request \"{Request}\" -> response \"{Response}\" at {@Duration} ms.", request, response, state.DurationMillis);

            return Task.CompletedTask;
        }
    }
}
