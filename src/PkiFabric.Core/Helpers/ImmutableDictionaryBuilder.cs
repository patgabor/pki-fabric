// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections;
using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// A builder type for creating <see cref="ImmutableDictionary{TKey, TValue}"/> instances efficiently.
/// </summary>
/// <typeparam name="TKey">The type of keys in the dictionary. Must be non-nullable.</typeparam>
/// <typeparam name="TValue">The type of values in the dictionary.</typeparam>
public readonly struct ImmutableDictionaryBuilder<TKey, TValue>(IEqualityComparer<TKey>? keyComparer = null, IEqualityComparer<TValue>? valueComparer = null)
    : IEnumerable<KeyValuePair<TKey, TValue>> where TKey : notnull
{
    private readonly ImmutableDictionary<TKey, TValue>.Builder _builder = ImmutableDictionary.CreateBuilder(keyComparer, valueComparer);
    /// <summary>
    /// Adds a key and value to the builder.
    /// </summary>
    /// <param name="key">The key of the element to add. Cannot be <see langword="null"/>.</param>
    /// <param name="value">The value of the element to add.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="key"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when an element with the same key already exists.</exception>
    public void Add(TKey key, TValue value) => _builder.Add(key, value);
    /// <summary>
    /// Adds a key-value pair to the builder.
    /// </summary>
    /// <param name="item">The key-value pair to add.</param>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="item"/>.Key is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">Thrown when an element with the same key already exists.</exception>
    public void Add(KeyValuePair<TKey, TValue> item) => _builder.Add(item);
    /// <summary>
    /// Gets or sets the element with the specified key.
    /// </summary>
    /// <returns>The element with the specified key.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="key"/> is null.</exception>
    /// <exception cref="KeyNotFoundException">The property is retrieved and <paramref name="key"/> is not found.</exception>
    /// <exception cref="NotSupportedException">The property is set and the <see cref="IDictionary{TKey, TValue}"/> is read-only.</exception>
    public TValue this[TKey key]
    {
        get => _builder[key];
        set => _builder[key] = value;
    }
    /// <summary>
    /// Creates an <see cref="ImmutableDictionary{TKey, TValue}"/> from the contents of this builder.
    /// </summary>
    /// <returns>An immutable dictionary containing all keys and values added to this builder.</returns>
    public ImmutableDictionary<TKey, TValue> ToImmutable() => _builder.ToImmutable();
    /// <summary>
    /// Returns an enumerator that iterates through the key-value pairs in the builder.
    /// </summary>
    /// <returns>An enumerator for the elements in the builder.</returns>
    public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator() => _builder.GetEnumerator();
    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
