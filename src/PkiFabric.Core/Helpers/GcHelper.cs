// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Diagnostics.CodeAnalysis;

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Forces garbage collection.
/// </summary>
public static class GcHelper
{
    /// <summary>
    /// Forces garbage collection.
    /// </summary>
    [SuppressMessage("Critical Code Smell", "S1215:\"GC.Collect\" should not be called",
        Justification = "We want to call this when exiting to prevent segfault on linux.")]
    public static void ClearAndWait()
    {
        GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive);
        GC.WaitForPendingFinalizers();
        GC.Collect();
    }
}
