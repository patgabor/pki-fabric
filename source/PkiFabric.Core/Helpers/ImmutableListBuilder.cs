using System.Collections;
using System.Collections.Immutable;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// A builder type for efficiently creating <see cref="ImmutableList{T}"/> instances.
/// </summary>
/// <typeparam name="T">The type of elements in the immutable list. Must be non-nullable.</typeparam>
public readonly struct ImmutableListBuilder<T>() : IEnumerable<T> where T : notnull
{
    private readonly ImmutableList<T>.Builder _builder = ImmutableList.CreateBuilder<T>();
    /// <summary>
    /// Adds an element to the builder.
    /// </summary>
    /// <param name="item">The element to add.</param>
    public void Add(T item) => _builder.Add(item);

    /// <summary>
    /// Creates an <see cref="ImmutableList{T}"/> containing all elements added to this builder.
    /// </summary>
    /// <returns>An immutable list containing the elements in the order they were added.</returns>
    public ImmutableList<T> ToImmutable() => _builder.ToImmutable();
    /// <summary>
    /// Returns an enumerator that iterates through the elements in the builder.
    /// </summary>
    /// <returns>An enumerator for the elements in the builder.</returns>
    public IEnumerator<T> GetEnumerator() => _builder.GetEnumerator();
    /// <inheritdoc/>
    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
