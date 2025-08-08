// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections;
using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// A builder type for efficiently creating <see cref="ImmutableArray{T}"/> instances.
/// </summary>
/// <typeparam name="T">The type of elements in the immutable array. Must be non-nullable.</typeparam>
public readonly struct ImmutableArrayBuilder<T>() : IEnumerable<T> where T : notnull
{
    private readonly ImmutableArray<T>.Builder _builder = ImmutableArray.CreateBuilder<T>();
    /// <summary>
    /// Creates an <see cref="ImmutableArray{T}"/> containing all elements added to this builder.
    /// </summary>
    /// <returns>An immutable array with the elements in their added order.</returns>
    public void Add(T item) => _builder.Add(item);
    /// <summary>
    /// Returns an enumerator that iterates through the elements in the builder.
    /// </summary>
    /// <returns>An enumerator for the elements in the builder.</returns>
    public ImmutableArray<T> ToImmutable() => _builder.ToImmutable();
    /// <summary>
    /// Returns an enumerator that iterates through the elements in the builder.
    /// </summary>
    /// <returns>An enumerator for the elements in the builder.</returns>
    public IEnumerator<T> GetEnumerator() => _builder.GetEnumerator();
    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
