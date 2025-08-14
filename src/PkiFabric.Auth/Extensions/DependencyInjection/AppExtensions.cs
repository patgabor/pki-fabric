// Copyright (c) PATGABOR. All rights reserved.
// Licensed under the Apache License 2.0 license.

using System.Reflection;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;

using FastEndpoints;
using FastEndpoints.Swagger;

using FluentValidation;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Json;

namespace PkiFabric.Auth.Extensions.DependencyInjection;

internal static class AppExtensions
{
    public static IServiceCollection UseAppEndpoints(this IServiceCollection @this)
    {
        ValidatorOptions.Global.DefaultRuleLevelCascadeMode = CascadeMode.Stop;

        return @this.AddFastEndpoints().SwaggerDocument(static swagger =>
        {
            swagger.MinEndpointVersion = 1;
            swagger.MaxEndpointVersion = 1;            
            swagger.EnableJWTBearerAuth = false;
            swagger.ShortSchemaNames = true;
            swagger.DocumentSettings = static document =>
            {
                Assembly assembly = typeof(Program).Assembly;
                document.Title = $"{assembly.GetName().Name} - v{assembly.GetName().Version?.ToString()}" ?? "n.a.";
                document.Description = "PkiFabric Auth API";
                document.Version = "v1";
                document.MarkNonNullablePropsAsRequired();
            };
        }).Configure<JsonOptions>(static json =>
        {
            json.SerializerOptions.IndentCharacter = ' ';
            json.SerializerOptions.WriteIndented = true;
            json.SerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
            json.SerializerOptions.NewLine = "\n";
            json.SerializerOptions.Encoder = JavaScriptEncoder.Default;
            json.SerializerOptions.Converters.Add(
                new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false));
        });
    }

    public static IApplicationBuilder MapAppEndpoints(this IApplicationBuilder @this)
    {
        return @this.UseFastEndpoints(static options =>
        {
            options.Endpoints.Configurator = static endpoints =>
            {
                endpoints.PreProcessor<EndpointLogging.PreProcessor>(Order.Before);
                endpoints.PostProcessor<EndpointLogging.PostProcessor>(Order.After);
            };
            options.Endpoints.RoutePrefix = "api";
            options.Versioning.Prefix = "v";
        }).UseSwaggerGen();
    }
}
