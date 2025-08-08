// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Defines a type-specific adapter that converts the implementing instance to a <typeparamref name="TTarget"/>.
/// </summary>
/// <typeparam name="TSource">The type to adapt from. Must be non-nullable.</typeparam>
/// <typeparam name="TTarget">The type to adapt to. Must be non-nullable.</typeparam>
public interface IAdapter<in TSource, out TTarget>
    where TSource : notnull
    where TTarget : notnull
{
    /// <summary>
    /// Converts the input instance of <typeparamref name="TSource"/> to an instance of <typeparamref name="TTarget"/>.
    /// </summary>
    /// <param name="source">The instance to convert from.</param>
    /// <returns>A non-null instance of <typeparamref name="TTarget"/>.</returns>
    TTarget Adapt(TSource source);
}