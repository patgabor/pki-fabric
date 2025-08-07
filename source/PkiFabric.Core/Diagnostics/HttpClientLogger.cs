// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Globalization;

using Microsoft.Extensions.Http.Logging;
using Microsoft.Extensions.Logging;

namespace PkiFabric.Core.Diagnostics;

/// <summary>
/// Provides logging functionality for HTTP client requests, including start, stop, and failure events.
/// </summary>
public sealed class HttpClientLogger(ILogger<HttpClientLogger> logger) : IHttpClientLogger
{
    private const string FallbackStatusCode = "Unknown";

    // "F" or "f" -> Fixed-point -> Result: Integral and decimal digits with optional negative sign.
    private const string ElapsedMillisecondsFormat = "F1";

    /// <inheritdoc/>
    public void LogRequestFailed(object? context, HttpRequestMessage request, HttpResponseMessage? response, Exception exception, TimeSpan elapsed)
    {
        logger.LogWarning(
            exception,
            "Request to {Host}{Path} with method {Method} failed after {Elapsed}ms with status code {StatusCode}.",
            request.RequestUri?.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped),
            request.RequestUri?.PathAndQuery,
            request.Method,
            elapsed.TotalMilliseconds.ToString(ElapsedMillisecondsFormat, NumberFormatInfo.InvariantInfo),
            response?.StatusCode.ToString() ?? FallbackStatusCode);
    }

    /// <inheritdoc/>
    public object? LogRequestStart(HttpRequestMessage request)
    {
        logger.LogDebug(
            "Starting request to {Host}{Path} with method {Method}.",
            request.RequestUri?.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped),
            request.RequestUri?.PathAndQuery,
            request.Method);

        return null; // No specific "context" to return
    }

    /// <inheritdoc/>
    public void LogRequestStop(object? context, HttpRequestMessage request, HttpResponseMessage response, TimeSpan elapsed)
    {
        // No specific "context" to work on
        logger.LogDebug("Stopping request to {Host}{Path} with method {Method} after {Elapsed}ms with status code {StatusCode}.",
            request.RequestUri?.GetComponents(UriComponents.SchemeAndServer, UriFormat.Unescaped),
            request.RequestUri?.PathAndQuery,
            request.Method,
            elapsed.TotalMilliseconds.ToString(ElapsedMillisecondsFormat, NumberFormatInfo.InvariantInfo),
            response?.StatusCode.ToString() ?? FallbackStatusCode);
    }
}
