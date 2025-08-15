// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

namespace PkiFabric.Core.Security;
/// <summary>
/// Default implementation of <see cref="IPasswordEntropyHelper"/> for estimating
/// password entropy and classifying password strength.
/// </summary>
/// <remarks>
/// This helper calculates entropy based on the size of the detected character set
/// (lowercase letters, uppercase letters, digits, special characters) multiplied by
/// the length of the password, using the formula:
/// <c>entropy = log2(characterSetSize) * passwordLength</c>.
/// </remarks>
public sealed class DefaultPasswordEntropyHelper : IPasswordEntropyHelper
{
    /// <summary>
    /// Calculates the estimated entropy of the given password.
    /// </summary>
    /// <param name="password">The password to evaluate.</param>
    /// <returns>
    /// The estimated entropy (in bits). Returns <c>0.0</c> if the password is null or empty.
    /// </returns>
    /// <remarks>
    /// This method determines which types of characters are used in the password:
    /// lowercase letters (26), uppercase letters (26), digits (10), and special characters (≈32).
    /// The combined size of the used character set is then used to calculate entropy.
    /// </remarks>
    public double ComputeEntropy(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return 0.0;
        }

        bool hasLower = false;
        bool hasUpper = false;
        bool hasDigit = false;
        bool hasSpecial = false;

        // Single pass over the password
        foreach (char @char in password)
        {
            if (!hasLower && char.IsLower(@char))
            {
                hasLower = true;
            }
            else if (!hasUpper && char.IsUpper(@char))
            {
                hasUpper = true;
            }
            else if (!hasDigit && char.IsDigit(@char))
            {
                hasDigit = true;
            }
            else if (!hasSpecial && !char.IsLetterOrDigit(@char))
            {
                hasSpecial = true;
            }

            // Early exit if all possible character types found
            if (hasLower && hasUpper && hasDigit && hasSpecial)
            {
                break;
            }
        }

        int characterSetSize = 0;
        if (hasLower)
        {
            characterSetSize += 26;
        }
        if (hasUpper)
        {
            characterSetSize += 26;
        }
        if (hasDigit)
        {
            characterSetSize += 10;
        }
        if (hasSpecial)
        {
            characterSetSize += 32; // Special: ~32 (common ASCII specials)
        }

        return Math.Log2(characterSetSize) * password.Length;
    }
    /// <summary>
    /// Classifies the password strength based on a given entropy value.
    /// </summary>
    /// <param name="entropy">The entropy value (in bits) previously calculated.</param>
    /// <returns>
    /// A <see cref="PasswordSecurityLevel"/> value describing the password quality:
    /// <list type="bullet">
    /// <item><description><see cref="PasswordSecurityLevel.Blank"/>: no password entered (0 bits)</description></item>
    /// <item><description><see cref="PasswordSecurityLevel.VeryWeak"/>: less than 20 bits</description></item>
    /// <item><description><see cref="PasswordSecurityLevel.Weak"/>: 20–49 bits</description></item>
    /// <item><description><see cref="PasswordSecurityLevel.Good"/>: 50–69 bits</description></item>
    /// <item><description><see cref="PasswordSecurityLevel.Strong"/>: 70 bits or more</description></item>
    /// </list>
    /// </returns>
    public PasswordSecurityLevel EvaluateStrength(double entropy) => entropy switch
    {
        0.0 => PasswordSecurityLevel.Blank,
        < 20.0 => PasswordSecurityLevel.VeryWeak,
        < 50.0 => PasswordSecurityLevel.Weak,
        < 70.0 => PasswordSecurityLevel.Good,
        >= 70.0 => PasswordSecurityLevel.Strong,
        _ => PasswordSecurityLevel.Blank,
    };
}
