using Microsoft.Extensions.Options;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;

/// <summary>
/// Provides the OpenIddictClientRegistration at runtime which is usually set in once in the startup.
/// This is only done so the `Issuer` url can be changed!
/// 
///     services.AddOpenIddict()
///         // Register the OpenIddict core components.
///         .AddCore(options =>
///         {
///         })
///         // Register the OpenIddict client components.
///         .AddClient(options =>
///         {
///             options.AddRegistration(new OpenIddictClientRegistration
///             {
///                 Issuer = new Uri("http://localhost:44349", UriKind.Absolute),
///                 ProviderName = "Local",
///                 ...
///             }
///             ...
///         }
/// </summary>
public class OpenIddictClientOptionsConfigurator : IConfigureOptions<OpenIddictClientOptions>
{
    private readonly IClientRegistrationProvider _configProvider;

    public OpenIddictClientOptionsConfigurator(IClientRegistrationProvider userConfiguredProvider)
    {
        _configProvider = userConfiguredProvider;
    }

    public void Configure(OpenIddictClientOptions options)
    {
        // Clear existing registrations to avoid duplicates
        options.Registrations.Clear();

        // Add the user-configured registration
        options.Registrations.Add(_configProvider.Provide());
    }
}
