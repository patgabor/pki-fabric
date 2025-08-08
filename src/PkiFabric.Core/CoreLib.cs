// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Reflection;

namespace PkiFabric.Core;

/// <summary>
/// CoreLib is a static class that provides access to the assembly of the Core library.
/// </summary>
public static class CoreLib
{
    /// <summary>
    /// Gets the assembly of the Core library.
    /// </summary>
    public static Assembly Assembly => typeof(CoreLib).Assembly;
}
