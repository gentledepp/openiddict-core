using Microsoft.Extensions.Primitives;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;

/// <summary>
/// The central configuration class that allows for changing the issuerurl at runtime
/// </summary>
public class ClientRegistrationProvider : IClientRegistrationProvider
{
    private Uri? _issuer;
    
    public ClientRegistrationProvider()
    {
    }

    public void SetIssuer(Uri issuer)
    {
        if (!issuer.IsAbsoluteUri)
            throw new ArgumentException("must be absolute Uri", nameof(issuer));

        _issuer = issuer;

        NotifyChanged();
    }

    public OpenIddictClientRegistration Provide()
    {
        return new OpenIddictClientRegistration
        {
            Issuer = _issuer ?? new Uri("http://localhost:44349", UriKind.Absolute),
            ProviderName = "Local",

            ClientId = "avalonia",

            // This sample uses protocol activations with a custom URI scheme to handle callbacks.
            //
            // For more information on how to construct private-use URI schemes,
            // read https://www.rfc-editor.org/rfc/rfc8252#section-7.1 and
            // https://www.rfc-editor.org/rfc/rfc7595#section-3.8.
            PostLogoutRedirectUri = new Uri("com.openiddict.sandbox.avalonia.client:/callback/logout/local", UriKind.Absolute),
            RedirectUri = new Uri("com.openiddict.sandbox.avalonia.client:/callback/login/local", UriKind.Absolute),

            Scopes = { Scopes.Email, Scopes.Profile, Scopes.OfflineAccess, "demo_api" }
        };
    }

    /// see: https://medium.com/@gokerakce/how-to-use-change-tokens-in-net-7-3db9cc43910f
    /// <summary>
    /// Rest of the class related to the change tracking feature.
    /// If you need to track the guest list you can use the Watch() method.
    /// </summary>
    /// 
    private CancellationTokenSource? _cancellationTokenSource;


    public IChangeToken Watch()
    {

        if(_cancellationTokenSource != null )
            return new CancellationChangeToken(_cancellationTokenSource.Token);

        _cancellationTokenSource?.Dispose();
        _cancellationTokenSource = new CancellationTokenSource();

        return new CancellationChangeToken(_cancellationTokenSource.Token);
    }

    private void NotifyChanged()
    {
        var cts = _cancellationTokenSource;
        _cancellationTokenSource = null;
        cts?.Cancel();
    }
}
