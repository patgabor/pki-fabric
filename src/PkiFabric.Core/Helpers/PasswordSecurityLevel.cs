// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Defines the strength categories for a password based on its calculated entropy.
/// </summary>
public enum PasswordSecurityLevel
{
    /// <summary>
    /// No password entered or entropy is zero.
    /// </summary>
    Blank,

    /// <summary>
    /// Extremely weak password, typically less than 20 bits of entropy.
    /// </summary>
    VeryWeak,

    /// <summary>
    /// Weak password, typically between 20 and 49 bits of entropy.
    /// </summary>
    Weak,

    /// <summary>
    /// Good password, typically between 50 and 69 bits of entropy.
    /// </summary>
    Good,

    /// <summary>
    /// Strong password, generally 70 bits of entropy or more.
    /// </summary>
    Strong
}
