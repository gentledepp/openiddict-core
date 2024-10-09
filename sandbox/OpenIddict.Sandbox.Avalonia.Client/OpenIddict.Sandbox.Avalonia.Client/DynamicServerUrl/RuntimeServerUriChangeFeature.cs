using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;

public static class RuntimeServerUriChangeFeature
{
    public static IServiceCollection AddSupportForRuntimeServerUriChange(this IServiceCollection services)
    {
        services.AddSingleton<IConfigureOptions<OpenIddictClientOptions>, OpenIddictClientOptionsConfigurator>();
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddictClientOptions>, OpenIddictClientOptionsChangeTokenSource>();
        services.AddSingleton<IClientRegistrationProvider, ClientRegistrationProvider>();
        services.AddSingleton<IOptionsChangeTokenSource<OpenIddictClientOptions>, OpenIddictClientOptionsChangeTokenSource>();

        return services;
    }
}