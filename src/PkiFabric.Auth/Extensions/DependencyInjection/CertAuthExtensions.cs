// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authorization;

namespace PkiFabric.Auth.Extensions.DependencyInjection;

internal static class CertAuthExtensions
{
    public const string RestrictedEndpoint = nameof(RestrictedEndpoint);

    private const int CacheSize = 1_000;
    private static readonly TimeSpan s_cacheDuration = TimeSpan.FromMinutes(5);

    public static IServiceCollection AddClientCertAuthentication(this IServiceCollection services)
    {
        AuthenticationBuilder auth = services.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme);

        _ = auth.AddCertificate(static authentication =>
        {
            authentication.AllowedCertificateTypes = CertificateTypes.Chained;
            authentication.RevocationFlag = X509RevocationFlag.EntireChain;
            authentication.RevocationMode = X509RevocationMode.Online;
            authentication.ValidateCertificateUse = true; // EKU
            authentication.ValidateValidityPeriod = true; // Validity period / expiration

            authentication.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = s_assignCertClaimsAsync,
                OnAuthenticationFailed = s_authFailedAsync
            };
        });
        // Add a certificate cache to improve performance
        _ = auth.AddCertificateCache(static options =>
        {
            options.CacheSize = CacheSize;
            options.CacheEntryExpiration = s_cacheDuration;
        });
        return services;
    }

    public static IServiceCollection AddClientCertAuthorization(this IServiceCollection services)
    {        
        return services.AddAuthorization(static authorization =>
        {
            authorization.AddPolicy(RestrictedEndpoint, s_withCertClaims);
        });
    }

    private static readonly Action<AuthorizationPolicyBuilder> s_withCertClaims = static policy =>
    {
        policy.RequireAuthenticatedUser();

        policy.RequireClaim(ClaimTypes.Name);
        policy.RequireClaim(ClaimTypes.SerialNumber);
        policy.RequireClaim(ClaimTypes.Thumbprint);
        policy.RequireClaim(ClaimTypes.X500DistinguishedName);
    };

    private static readonly Func<CertificateValidatedContext, Task> s_assignCertClaimsAsync = static context =>
    {
        // Assign the certificate to the user claims
        X509Certificate2 cert = context.ClientCertificate;
        string issuer = cert.Issuer;
        context.Principal ??= new ClaimsPrincipal();
        context.Principal.AddIdentity(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, cert.Subject,ClaimValueTypes.String, issuer),
            new Claim(ClaimTypes.SerialNumber, cert.GetSerialNumberString(),ClaimValueTypes.HexBinary, issuer),
            new Claim(ClaimTypes.Thumbprint, cert.Thumbprint,ClaimValueTypes.HexBinary, issuer),
            new Claim(ClaimTypes.X500DistinguishedName, cert.Subject,ClaimValueTypes.X500Name, issuer)
        }));

        context.Success();

        return Task.CompletedTask;
    };

    private static readonly Func<CertificateAuthenticationFailedContext, Task> s_authFailedAsync = static context =>
    {
        X509Certificate2? x509Certificate2 = context.HttpContext.Connection.ClientCertificate;

        if (x509Certificate2 is not null)
        {
            context.Fail($"Certificate authentication failed for {x509Certificate2.Subject}. Reason: {context.Exception.Message}.");
        }
        else
        {
            context.Fail("Certificate authentication failed, no client certificate provided.");
        }

        return Task.CompletedTask;
    };
}
