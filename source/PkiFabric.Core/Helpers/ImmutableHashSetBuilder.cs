// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections;
using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// A builder type for efficiently constructing <see cref="ImmutableHashSet{T}"/> instances.
/// </summary>
/// <typeparam name="T">The type of elements in the immutable hash set. Must be non-nullable.</typeparam>
public readonly struct ImmutableHashSetBuilder<T>(IEqualityComparer<T>? comparer = null) : IEnumerable<T> where T : notnull
{
    private readonly ImmutableHashSet<T>.Builder _builder = ImmutableHashSet.CreateBuilder(comparer);
    /// <summary>
    /// Adds an element to the builder.
    /// </summary>
    /// <param name="item">The element to add.</param>
    /// <returns>
    /// <see langword="true"/> if the element was added to the set; <see langword="false"/> if the element was already present.
    /// </returns>
    public void Add(T item) => _builder.Add(item);
    /// <summary>
    /// Creates an <see cref="ImmutableHashSet{T}"/> containing all elements added to this builder.
    /// </summary>
    /// <returns>An immutable hash set containing all unique elements added to the builder.</returns>
    public ImmutableHashSet<T> ToImmutable() => _builder.ToImmutable();
    /// <summary>
    /// Returns an enumerator that iterates through the elements in the builder.
    /// </summary>
    /// <returns>An enumerator for the elements in the builder.</returns>
    public IEnumerator<T> GetEnumerator() => _builder.GetEnumerator();
    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
