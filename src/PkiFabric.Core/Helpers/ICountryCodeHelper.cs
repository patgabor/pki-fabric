// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Contains ISO 3166-1 alpha-2 country codes for all specific cultures.
/// </summary>
public interface ICountryCodeHelper
{
    /// <summary>
    /// Contains ISO 3166-1 alpha-2 country codes for all specific cultures.
    /// </summary>
    IReadOnlySet<string> Codes { get; }
}
