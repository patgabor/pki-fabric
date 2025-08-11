// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Collections.Frozen;
using System.Globalization;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Contains ISO 3166-1 alpha-2 country codes for all specific cultures.
/// </summary>
public sealed class DefaultCountryCodeHelper : ICountryCodeHelper
{

    /// <inheritdoc/>
    public IReadOnlySet<string> Codes => s_cache;

    private static readonly FrozenSet<string> s_cache = CreateCodes();

    /// <summary>
    /// Returns the two letter ISO region names (ie: US)
    /// </summary>
    private static FrozenSet<string> CreateCodes()
    {
        List<string> codes = [];
        foreach (CultureInfo item in CultureInfo.GetCultures(CultureTypes.SpecificCultures))
        {
            RegionInfo region = new(item.Name);
            codes.Add(region.TwoLetterISORegionName);
        }
        return codes.ToFrozenSet(StringComparer.Ordinal);
    }
}
