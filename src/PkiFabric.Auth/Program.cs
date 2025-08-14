// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;

using PkiFabric.Auth.Extensions.DependencyInjection;
using PkiFabric.Core.Extensions.DependencyInjection;
using PkiFabric.Core.Helpers;

try
{
    WebApplicationBuilder builder = WebApplication.CreateBuilder(
        new WebApplicationOptions { ContentRootPath = AppContext.BaseDirectory, Args = args });

    builder.Host.UseDefaultServiceProvider(static (context, serviceProvider) =>
    {
        serviceProvider.ValidateScopes = true;
        serviceProvider.ValidateOnBuild = true;
    });
    builder.Host.AddApplicationSettings();
    builder.Host.AddApplicationLogging();

    // Add services to the container.

    builder.Services.UseAppEndpoints();
    builder.Services.AddClientCertAuthentication();
    builder.Services.AddClientCertAuthorization();
    builder.Services.AddStartupHealthChecks();
    builder.Services.AddCoreHealthChecks();

    builder.WebHost.ConfigureKestrel(static kestrel =>
    {
        kestrel.AddServerHeader = false;
        kestrel.ConfigureHttpsDefaults(static https =>
        {
            https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
            https.AllowAnyClientCertificate();
        });
    });

    await using WebApplication app = builder.Build();

    // middleware order to folow:
    // https://learn.microsoft.com/en-us/aspnet/core/fundamentals/middleware/?view=aspnetcore-9.0

    app.UseApplicationExceptionHandler();
    app.UseHttpsRedirection();
    app.UseRouting();
    app.UseAuthentication();
    app.UseAuthorization();

    app.MapAppEndpoints();
    app.MapHealthCheckEndpoints();

    await app.RunAsync();
}
finally
{
    GcHelper.ClearAndWait();
}
