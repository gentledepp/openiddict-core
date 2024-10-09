using Microsoft.Extensions.Primitives;
using OpenIddict.Client;

namespace OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;

public interface IClientRegistrationProvider
{
    /// <summary>
    /// Allows to change the issuer url at runtime
    /// </summary>
    /// <param name="issuer"></param>
    void SetIssuer(Uri issuer);
    /// <summary>
    /// Returns an updated configuration with the currently configured issuer uri
    /// </summary>
    /// <returns></returns>
    OpenIddictClientRegistration Provide();
    /// <summary>
    /// Provides a change token, so the options system can be notified when the issuer was changed
    /// </summary>
    /// <returns></returns>
    public IChangeToken Watch();
}
