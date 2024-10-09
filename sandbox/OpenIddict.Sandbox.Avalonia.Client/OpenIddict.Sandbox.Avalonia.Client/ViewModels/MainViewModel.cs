using OpenIddict.Abstractions;
using OpenIddict.Client;
using OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;
using ReactiveUI;
using System.Reactive;
using System.Reactive.Linq;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace OpenIddict.Sandbox.Avalonia.Client.ViewModels;

public class MainViewModel : ViewModelBase
{

    private OpenIddictClientService _service;
    private readonly IClientRegistrationProvider _configurator;
    private string _message = string.Empty;
    private string _serverUrl = "https://localhost:44395";
    private string? _tenancyName;
    private bool _isEnabled = true;
    CancellationTokenSource? _source;

    public MainViewModel(OpenIddictClientService service,
        IClientRegistrationProvider configurator)
    {
        _service = service;
        _configurator = configurator;

        var canExecute = this.WhenAnyValue(v => v.IsEnabled);

        LoginCommand = ReactiveCommand.CreateFromTask(LoginAsync, canExecute);
        LoginWithGithubCommand = ReactiveCommand.CreateFromTask(LoginWithGithubAsync, canExecute);
        LogoutCommand = ReactiveCommand.CreateFromTask(LogoutAsync, canExecute);
        CancelCommand = ReactiveCommand.CreateFromTask(CancelAsync, canExecute.Select(v => !v));

        // when the server url changes and it is a valid, absolute uri,
        // then update the issuer using the IClientRegistrationProvider
        this.WhenAnyValue(v => v.ServerUrl).Where(s => s != null && Uri.TryCreate(s, UriKind.Absolute, out var _))
            .Throttle(TimeSpan.FromMilliseconds(250))
            .ObserveOn(RxApp.MainThreadScheduler)
            .Subscribe(url =>
            {
                var serverUrl = new Uri(url, UriKind.Absolute);
                _configurator.SetIssuer(serverUrl);
            });

        Message = "Enter your server url to login";
    }

    public ReactiveCommand<Unit, Unit> LoginCommand { get; }
    public ReactiveCommand<Unit, Unit> LoginWithGithubCommand { get; }
    public ReactiveCommand<Unit, Unit> LogoutCommand { get; }
    public ReactiveCommand<Unit, Unit> CancelCommand { get; }

    public string ServerUrl
    {
        get { return _serverUrl; }
        set { this.RaiseAndSetIfChanged(ref _serverUrl, value); }
    }

    public string? TenancyName
    {
        get { return _tenancyName; }
        set { this.RaiseAndSetIfChanged(ref _tenancyName, value); }
    }

    public string Message
    {
        get { return _message; }
        set { this.RaiseAndSetIfChanged(ref _message, value); }
    }

    public bool IsEnabled
    {
        get { return _isEnabled; }
        set { this.RaiseAndSetIfChanged(ref _isEnabled, value); }
    }

    private async Task LoginAsync()
    {
        await LogInAsync("Local");
    }

    private async Task LoginWithGithubAsync()
    {
        await LogInAsync("Local", new()
        {
            [Parameters.IdentityProvider] = "GitHub"
        });
    }
    
    private async Task LogoutAsync()
    {
        await LogOutAsync("Local");
    }

    private async Task LogInAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        IsEnabled = false;

        try
        {
            _source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            if (parameters != null)
                parameters["tenancyName"] = TenancyName;
            else
                parameters = new()
                {
                    ["tenancyName"] = TenancyName
                };

            try
            {
                // Ask OpenIddict to initiate the authentication flow (typically, by starting the system browser).
                var result = await _service.ChallengeInteractivelyAsync(new()
                {
                    AdditionalAuthorizationRequestParameters = parameters,
                    CancellationToken = _source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the authorization process.
                var principal = (await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = _source.Token,
                    Nonce = result.Nonce
                })).Principal;

                Message = $"Welcome, {principal.FindFirst(Claims.Name)!.Value}.";
            }

            catch (OperationCanceledException)
            {
                Message = "The authentication process was aborted.";
            }

            catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
            {
                Message = "The authorization was denied by the end user.";
            }

            catch
            {
                Message = "An error occurred while trying to authenticate the user.";
            }
        }

        finally
        {
            _source?.Dispose();
            // Re-enable the buttons to allow starting a new operation.
            IsEnabled = true;
        }
    }

    private async Task LogOutAsync(string provider, Dictionary<string, OpenIddictParameter>? parameters = null)
    {
        // Disable the buttons to prevent concurrent operations.
        IsEnabled = false;

        try
        {
            using var source = new CancellationTokenSource(delay: TimeSpan.FromSeconds(90));

            try
            {
                // Ask OpenIddict to initiate the logout flow (typically, by starting the system browser).
                var result = await _service.SignOutInteractivelyAsync(new()
                {
                    AdditionalLogoutRequestParameters = parameters,
                    CancellationToken = source.Token,
                    ProviderName = provider
                });

                // Wait for the user to complete the logout process and authenticate the callback request.
                //
                // Note: in this case, only the claims contained in the state token can be resolved since
                // the authorization server doesn't return any other user identity during a logout dance.
                await _service.AuthenticateInteractivelyAsync(new()
                {
                    CancellationToken = source.Token,
                    Nonce = result.Nonce
                });

                Message = "The user was successfully logged out from the local server.";
            }

            catch (OperationCanceledException)
            {
                Message = "The logout process was aborted.";
            }

            catch
            {
                Message = "An error occurred while trying to log the user out.";
            }
        }

        finally
        {
            // Re-enable the buttons to allow starting a new operation.
            IsEnabled = true;
        }
    }

    private Task CancelAsync()
    {

        if (IsEnabled)
            return Task.CompletedTask;

        if (_source is null)
            return Task.CompletedTask;

        _source.Cancel();

        return Task.CompletedTask;
    }

}
