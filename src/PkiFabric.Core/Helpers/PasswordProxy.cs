// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Runtime.InteropServices;

using Org.BouncyCastle.OpenSsl;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Provides a securely pinned and disposable password buffer to supply passwords to BouncyCastle.
/// The password is stored as a pinned <see cref="char"/> array to prevent relocation by the GC,
/// and is cleared from memory when disposed to reduce sensitive data exposure.
/// </summary>
public sealed class PasswordProxy : IPasswordFinder, IDisposable
{
    private readonly char[] _passwordChars;
    private readonly GCHandle _pinnedHandle;
    private bool _disposed;

    /// <summary>
    /// Ctor that initializes the password proxy with a given password.
    /// </summary>
    public PasswordProxy(ReadOnlySpan<char> password)
    {
        _passwordChars = password.ToArray();
        _pinnedHandle = GCHandle.Alloc(_passwordChars, GCHandleType.Pinned);
    }

    /// <summary>
    /// Ctor that initializes the password proxy with a given password.
    /// </summary>
    public PasswordProxy(string password) : this(password.AsSpan()) { }

    /// <summary>
    /// Retrieves the underlying pinned password character array.
    /// </summary>
    /// <returns>
    /// The <see cref="char"/> array containing the password characters.
    /// </returns>
    /// <exception cref="ObjectDisposedException">
    /// Thrown if the instance has already been disposed, indicating the password buffer is no longer available.
    /// </exception>
    /// <remarks>
    /// This method returns the internal password buffer directly; callers should treat this array as sensitive and avoid modifying it.
    /// The password array remains pinned in memory for the lifetime of this object to reduce exposure risk.
    /// </remarks>
    public char[] GetPassword()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        return _passwordChars;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed)
        {
            return;
        }

        if (disposing)
        {
            // Clear and free sensitive resources
            Array.Clear(_passwordChars, 0, _passwordChars.Length);
        }

        if (_pinnedHandle.IsAllocated)
        {
            _pinnedHandle.Free();
        }

        _disposed = true;
    }

    /// <summary>
    /// Finalizer only called if Dispose was not called.
    /// </summary>
    ~PasswordProxy()
    {
        Dispose(false);
    }
}
