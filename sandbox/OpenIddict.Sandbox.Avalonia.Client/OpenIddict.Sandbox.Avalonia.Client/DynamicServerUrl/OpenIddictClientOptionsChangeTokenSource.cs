using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;

/// <summary>
/// A glue class that is used by the Microsoft.Extensions.Options framework to get a change token associated with the OpenIddictClientOptions.
/// Note: This is only called once the OpenIddictClientOptions were requested for the first time (so: lazily)
/// You first have to click "login" once for this to kick in!
/// </summary>
public class OpenIddictClientOptionsChangeTokenSource : IOptionsChangeTokenSource<OpenIddictClientOptions>
{
    private readonly IClientRegistrationProvider _configuration;

    public OpenIddictClientOptionsChangeTokenSource(IClientRegistrationProvider configuration)
    {
        _configuration = configuration;
    }

    public string Name => Microsoft.Extensions.Options.Options.DefaultName;

    public IChangeToken GetChangeToken()
    {
        return _configuration.Watch();
    }
}
