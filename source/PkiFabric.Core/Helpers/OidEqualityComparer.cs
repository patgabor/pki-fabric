using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

using CommunityToolkit.Diagnostics;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Provides a type-specific equality comparer for <see cref="Oid"/> objects, 
/// comparing their <see cref="Oid.Value"/> properties using ordinal string comparison.
/// </summary>
/// <remarks>
/// This comparer is intended for use in collections or algorithms that require hashing or equality 
/// comparison of <see cref="Oid"/> instances based solely on the <see cref="Oid.Value"/> property.
/// </remarks>
public sealed class OidEqualityComparer : IEqualityComparer<Oid>
{
    /// <summary>
    /// Gets a default instance of <see cref="OidEqualityComparer"/> that compares <see cref="Oid"/> objects by their <see cref="Oid.Value"/> property.
    /// </summary>
    public static IEqualityComparer<Oid> Default { get; } = new OidEqualityComparer();
    /// <summary>
    /// Determines whether the specified <see cref="Oid"/> objects are equal by comparing their <see cref="Oid.Value"/> properties using ordinal string comparison.
    /// </summary>
    /// <param name="x">The first <see cref="Oid"/> to compare.</param>
    /// <param name="y">The second <see cref="Oid"/> to compare.</param>
    /// <returns><see langword="true"/> if the <see cref="Oid.Value"/> properties of <paramref name="x"/> and <paramref name="y"/> are equal; otherwise, <see langword="false"/>.</returns>
    public bool Equals(Oid? x, Oid? y)
    {
        if (ReferenceEquals(x, y))
        {
            return true;
        }
        if (x is null || y is null)
        {
            return false;
        }
        return StringComparer.Ordinal.Equals(x.Value, y.Value);
    }
    /// <summary>
    /// Returns a hash code for the specified <see cref="Oid"/> instance based on its <see cref="Oid.Value"/> property.
    /// </summary>
    /// <param name="obj">The <see cref="Oid"/> instance for which to get a hash code. The value cannot be <see langword="null"/>.</param>
    /// <returns>A hash code for the current <see cref="Oid"/>.</returns>
    /// <exception cref="ArgumentNullException">Thrown if <paramref name="obj"/> is <see langword="null"/>.</exception>
    public int GetHashCode([DisallowNull] Oid obj)
    {
        Guard.IsNotNull(obj);

        // Since null is disallowed, no runtime check for null is needed.
        // The OID's Value property uniquely identifies the OID for most practical and .NET cryptography scenarios.
        // Null-coalesce to empty string in case Value is unexpectedly null.
        return StringComparer.Ordinal.GetHashCode(obj.Value ?? string.Empty);
    }
}
