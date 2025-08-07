using System.Collections;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.Extensions.Logging;
using PkiFabric.Core.Helpers;

namespace PkiFabric.Core.Diagnostics;

internal sealed class DefaultExceptionHandler(ILogger<DefaultExceptionHandler> logger) : IExceptionHandler
{
    private const string FallbackPath = "Unknown";

    private readonly ILogger<DefaultExceptionHandler> _logger = logger;

    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        string route = httpContext.Request.Path.Value ?? FallbackPath;
        Dictionary<string, object?> reason = Reason(exception);

        _logger.LogError(exception, "An unhandled exception occurred at {Route} due to reason: {@Reason}.", route, reason);

        ProblemHttpResult problem = HttpExceptionAdapter.Default.Adapt(exception);
        problem.ProblemDetails.Extensions["Route"] = route;
        problem.ProblemDetails.Extensions["CorrelationId"] = httpContext.TraceIdentifier;

        httpContext.Response.Headers["X-Correlation-ID"] = httpContext.TraceIdentifier;

        await problem.ExecuteAsync(httpContext);

        return true;
    }

    private Dictionary<string, object?> Reason(Exception exception)
    {
        Dictionary<string, object?> reason = [];

        if (exception.InnerException is not null)
        {
            foreach (KeyValuePair<string, object?> item in Reason(exception.InnerException))
            {
                string key = item.Key.ToString() ?? item.Key.GetType().Name;
                if (reason.TryGetValue(key, out object? value))
                {
                    _logger.LogWarning("Duplicate key '{Key}' found in exception data. Overwriting previous value: {@Value}.", key, value);
                }
                reason[key] = item.Value;
            }
        }

        foreach (DictionaryEntry item in exception.Data)
        {
            string key = item.Key.ToString() ?? item.Key.GetType().Name;
            if (reason.TryGetValue(key, out object? value))
            {
                _logger.LogWarning("Duplicate key '{Key}' found in exception data. Overwriting previous value: {@Value}.", key, value);
            }
            reason[key] = item.Value;
        }

        return reason;
    }
}
