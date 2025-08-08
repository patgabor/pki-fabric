// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Frozen;
using System.Security;
using System.Security.Authentication;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Adapts an <see cref="Exception"/> instance to a standardized <see cref="ProblemHttpResult"/>
/// response, mapping common exception types to HTTP status codes and problem details.
/// </summary>
/// <remarks>
/// This adapter is intended for use within web APIs to consistently translate exceptions into
/// RFC 7807-compliant HTTP problem responses. It covers standard mapping for several known
/// exception types and supplies fallback information for unknown cases.
/// </remarks>
public sealed class HttpExceptionAdapter : IAdapter<Exception, ProblemHttpResult>
{
    /// <summary>
    /// Gets a default instance of <see cref="HttpExceptionAdapter"/>.
    /// </summary>
    public static HttpExceptionAdapter Default { get; } = new();

    private static readonly FrozenDictionary<int, (string Title, string Url)> s_codes = new[]
    {
        (StatusCodes.Status400BadRequest, ("Bad Request", "https://httpstatuses.com/400")),
        (StatusCodes.Status401Unauthorized, ("Unauthorized", "https://httpstatuses.com/401")),
        (StatusCodes.Status402PaymentRequired, ("Payment Required", "https://httpstatuses.com/402")),
        (StatusCodes.Status403Forbidden, ("Forbidden", "https://httpstatuses.com/403")),
        (StatusCodes.Status404NotFound, ("Not Found", "https://httpstatuses.com/404")),
        (StatusCodes.Status405MethodNotAllowed, ("Method Not Allowed", "https://httpstatuses.com/405")),
        (StatusCodes.Status406NotAcceptable, ("Not Acceptable", "https://httpstatuses.com/406")),
        (StatusCodes.Status408RequestTimeout, ("Request Timeout", "https://httpstatuses.com/408")),
        (StatusCodes.Status409Conflict, ("Conflict", "https://httpstatuses.com/409")),
        (StatusCodes.Status410Gone, ("Gone", "https://httpstatuses.com/410")),
        (StatusCodes.Status413PayloadTooLarge, ("Payload Too Large", "https://httpstatuses.com/413")),
        (StatusCodes.Status415UnsupportedMediaType, ("Unsupported Media Type", "https://httpstatuses.com/415")),
        (StatusCodes.Status422UnprocessableEntity, ("Unprocessable Entity", "https://httpstatuses.com/422")),
        (StatusCodes.Status426UpgradeRequired, ("Upgrade Required", "https://httpstatuses.com/426")),
        (StatusCodes.Status429TooManyRequests, ("Too Many Requests", "https://httpstatuses.com/429")),

        (StatusCodes.Status500InternalServerError, ("Internal Server Error", "https://httpstatuses.com/500")),
        (StatusCodes.Status501NotImplemented, ("Not Implemented", "https://httpstatuses.com/501")),
        (StatusCodes.Status502BadGateway, ("Bad Gateway", "https://httpstatuses.com/502")),
        (StatusCodes.Status503ServiceUnavailable, ("Service Unavailable", "https://httpstatuses.com/503")),
        (StatusCodes.Status504GatewayTimeout, ("Gateway Timeout", "https://httpstatuses.com/504")),
        (StatusCodes.Status507InsufficientStorage, ("Insufficient Storage", "https://httpstatuses.com/507")),
    }.ToFrozenDictionary(x => x.Item1, x => x.Item2);

    /// <summary>
    /// Maps common .NET exceptions to HTTP status codes.
    /// </summary>
    private static int StatusCode(Exception exception) => exception switch
    {
        // 400 Bad Request: Client input validation or invalid operation
        BadHttpRequestException or
        ArgumentException or
        ArgumentNullException or
        ArgumentOutOfRangeException or
        FormatException or
        InvalidOperationException
            => StatusCodes.Status400BadRequest,

        // 401 Unauthorized: Auth errors
        AuthenticationException => StatusCodes.Status401Unauthorized,

        // 403 Forbidden: Security/authorization errors
        SecurityException or
        UnauthorizedAccessException
            => StatusCodes.Status403Forbidden,

        // 404 Not Found: Missing resource/file
        KeyNotFoundException or
        FileNotFoundException or
        DirectoryNotFoundException
            => StatusCodes.Status404NotFound,

        // 405 Method Not Allowed: Method issues (rare, explicit in controllers/middleware)
        NotSupportedException => StatusCodes.Status405MethodNotAllowed,

        // 408 Request Timeout/Task Canceled
        TimeoutException or
        TaskCanceledException
            => StatusCodes.Status408RequestTimeout,

        // 422 Unprocessable Entity: Validation failures
        System.ComponentModel.DataAnnotations.ValidationException or
        FluentValidation.ValidationException
            => StatusCodes.Status422UnprocessableEntity,

        // 429 Too Many Requests: Throttling (usually handled at middleware/API gateway layer)
        // Could use custom exception.

        NotImplementedException => StatusCodes.Status501NotImplemented,

        // 503 Service Unavailable
        OperationCanceledException => StatusCodes.Status503ServiceUnavailable,

        // 500 Internal Server Error: Everything else
        _ => StatusCodes.Status500InternalServerError
    };


    private static string ErrorType(Exception exception)
        => s_codes.TryGetValue(StatusCode(exception), out var value) ? value.Url : "https://httpstatuses.com/500";

    private static string Title(Exception exception)
        => s_codes.TryGetValue(StatusCode(exception), out var value) ? value.Title : "Unknown Error";

    /// <summary>
    /// Converts the encapsulated <see cref="Exception"/> to a <see cref="ProblemHttpResult"/>, 
    /// mapping exception types to appropriate HTTP status codes and problem detail fields.
    /// </summary>
    /// <returns>
    /// A <see cref="ProblemHttpResult"/> suitable for returning to the client as a standardized
    /// RFC 7807 response.
    /// </returns>
    /// <remarks>
    /// The result will propagate the exception's message in the <c>detail</c> field, and use
    /// the mapped or default status, title, and type references. Callers should be aware that
    /// the exception's original message will be exposed in the HTTP response.
    /// </remarks>
    public ProblemHttpResult Adapt(Exception source)
        => TypedResults.Problem(
            detail: source.Message,
            statusCode: StatusCode(source),
            title: Title(source),
            type: ErrorType(source),
            extensions: null);
}
