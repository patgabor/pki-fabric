// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Data;

namespace PkiFabric.Core.Data;

/// <summary>
/// Factory interface for creating database connections.
/// </summary>
public interface IDbConnectionFactory
{
    /// <summary>
    /// Creates and returns a new synchronous database connection instance.
    /// The caller is responsible for opening and disposing the connection.
    /// </summary>
    /// <returns>A new <see cref="IDbConnection"/> instance.</returns>
    IDbConnection CreateConnection();

    /// <summary>
    /// Asynchronously creates and returns a new database connection instance.
    /// The caller is responsible for opening and disposing the connection.
    /// </summary>
    /// <param name="cancellationToken">Token to observe for cancellation.</param>
    /// <returns>A task that represents the asynchronous creation operation. The task result contains the new <see cref="IDbConnection"/> instance.</returns>
    Task<IDbConnection> CreateConnectionAsync(CancellationToken cancellationToken);
}
