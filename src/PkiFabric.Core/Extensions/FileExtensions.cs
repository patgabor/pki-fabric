// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using CommunityToolkit.Diagnostics;

namespace PkiFabric.Core.Extensions;

/// <summary>
/// Provides extension methods for <see cref="FileInfo"/> objects
/// </summary>
public static class FileExtensions
{
    /// <summary>
    /// Determines whether the specified file can be written to.
    /// </summary>
    /// <param name="this">
    /// The <see cref="FileInfo"/> instance representing the file to check.
    /// </param>
    /// <returns>
    /// True if the file exists and can be opened for writing without exceptions; otherwise, false.
    /// </returns>
    public static bool IsWritable(this FileInfo @this)
    {
        Guard.IsNotNull(@this);

        if (!@this.Exists || @this.IsReadOnly)
        {
            return false;
        }
        try
        {
            using FileStream stream = @this.Open(FileMode.Open, FileAccess.Write, FileShare.None);
            return true;

        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Determines whether the specified file can be read.
    /// </summary>
    /// <param name="this">
    /// The <see cref="FileInfo"/> instance representing the file to check.
    /// </param>
    /// <returns>
    /// True if the file exists and can be opened for reading without exceptions; otherwise, false.
    /// </returns>
    public static bool IsReadable(this FileInfo @this)
    {
        Guard.IsNotNull(@this);
        if (!@this.Exists)
        {
            return false;
        }
        try
        {
            using FileStream stream = @this.Open(FileMode.Open, FileAccess.Read, FileShare.Read);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
