// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Helpers;

/// <summary>
/// Estimating password entropy and classifying password strength.
/// </summary>
public interface IPasswordEntropyHelper
{
    /// <summary>
    /// Calculates the estimated entropy of the given password.
    /// </summary>
    double ComputeEntropy(string password);
    /// <summary>
    /// Classifies the password strength based on a given entropy value.
    /// </summary>
    PasswordSecurityLevel EvaluateStrength(double entropy);
}
