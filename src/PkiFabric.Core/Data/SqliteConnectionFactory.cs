// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Data;

using Microsoft.Data.Sqlite;

namespace PkiFabric.Core.Data;

/// <summary>
/// Factory for creating <see cref="SqliteConnection"/> database connections.
/// </summary>
public class SqliteConnectionFactory(string connectionString) : IDbConnectionFactory
{
    private readonly string _connectionString = connectionString;

    /// <inheritdoc/>
    public IDbConnection CreateConnection()
    {
        SqliteConnection db = new(_connectionString);
        db.Open();
        return db;
    }

    /// <inheritdoc/>
    public async Task<IDbConnection> CreateConnectionAsync(CancellationToken cancellationToken)
    {
        SqliteConnection db = new(_connectionString);
        await db.OpenAsync(cancellationToken);
        return db;
    }
}
