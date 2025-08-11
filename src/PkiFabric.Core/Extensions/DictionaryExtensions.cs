// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

using CommunityToolkit.Diagnostics;

namespace PkiFabric.Core.Extensions;

/// <summary>
/// Provides extension methods for <see cref="Dictionary{TKey, TValue}"/>.
/// </summary>
public static class DictionaryExtensions
{
    /// <summary>
    /// Gets the value associated with the specified key, or adds a new value if the key does not exist.
    /// Uses a direct reference to avoid multiple lookups and extra allocations.
    /// </summary>
    public static TValue GetOrAdd<TKey, TValue>(this Dictionary<TKey, TValue> @this, TKey key, TValue value) where TKey : notnull
    {
        Guard.IsNotNull(@this);
        ref TValue? existingValue = ref CollectionsMarshal.GetValueRefOrAddDefault(@this, key, out bool exists);
        if (exists)
        {
            return existingValue!;
        }
        existingValue = value;
        return value;
    }
    /// <summary>
    /// Gets the value associated with the specified key, or adds a new value
    /// created by the provided value factory if it does not exist.
    /// </summary>
    public static TValue GetOrAdd<TKey, TValue>(this Dictionary<TKey, TValue> @this, TKey key, Func<TKey, TValue> valueFactory) where TKey : notnull
    {
        Guard.IsNotNull(@this);
        ref TValue? existingValue = ref CollectionsMarshal.GetValueRefOrAddDefault(@this, key, out bool exists);
        if (exists)
        {
            return existingValue!;
        }

        TValue value = valueFactory(key);
        existingValue = value;
        return value;
    }
    /// <summary>
    /// Attempts to update an existing value for the given key.
    /// Does nothing if the key is not present.
    /// </summary>
    public static bool TryUpdate<TKey, TValue>(this Dictionary<TKey, TValue> @this, TKey key, TValue value) where TKey : notnull
    {
        Guard.IsNotNull(@this);
        ref TValue existingValue = ref CollectionsMarshal.GetValueRefOrNullRef(@this, key);
        if (Unsafe.IsNullRef(ref existingValue))
        {
            return false; // Key does not exist
        }
        existingValue = value;
        return true; // Successfully updated
    }
    /// <summary>
    /// Attempts to update an existing value for the given key
    /// using a function to compute the new value.
    /// </summary>
    public static bool TryUpdate<TKey, TValue>(this Dictionary<TKey, TValue> @this, TKey key, Func<TKey, TValue> updateFunc) where TKey : notnull
    {
        Guard.IsNotNull(@this);
        ref TValue existingValue = ref CollectionsMarshal.GetValueRefOrNullRef(@this, key);
        if (Unsafe.IsNullRef(ref existingValue))
        {
            return false; // Key does not exist
        }
        existingValue = updateFunc(key);
        return true; // Successfully updated
    }
}
