using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Sandbox.Avalonia.Client.DynamicServerUrl;
using OpenIddict.Sandbox.Avalonia.Client.OpenId;
using OpenIddict.Sandbox.Avalonia.Client.ViewModels;
using OpenIddict.Sandbox.Avalonia.Client.Views;

namespace OpenIddict.Sandbox.Avalonia.Client;

public partial class App : Application
{
    private IServiceCollection? _services;

    public IHost? GlobalHost { get; private set; }

    public override void Initialize()
    {
        AvaloniaXamlLoader.Load(this);
    }

    public void ConfigureServices(IServiceCollection services)
    {
        services.AddAuth();

        services.AddTransient<MainViewModel>();
        services.AddTransient<ViewLocator>();

        services.AddSupportForRuntimeServerUriChange();

        _services = services;
    }

    public IServiceProvider BuildServiceProvider()
    {
        var hostBuilder = CreateHostBuilder();
        var host = hostBuilder.Build();
        GlobalHost = host;
        return host.Services;
    }

    public override async void OnFrameworkInitializationCompleted()
    {
        var provider = GlobalHost!.Services;
        if (provider is null)
            throw new InvalidOperationException("DI initialization failed - provider is null");

        using var s = provider.CreateScope();

        // emulate maui behavior:
        provider.InitializeMauiInitializeServices();

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            window.DataContext = provider.GetRequiredService<MainViewModel>();
            desktop.MainWindow = window;

            desktop.Exit += (sender, args) =>
            {
                GlobalHost.StopAsync(TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
                GlobalHost.Dispose();
                GlobalHost = null;
            };

            // emulate MAUI behavior
            provider.InitializeMauiInitializeScopedService();
        }
        else if (ApplicationLifetime is ISingleViewApplicationLifetime singleViewPlatform)
        {
            var window = new MainView();
            window.DataContext = provider.GetRequiredService<MainViewModel>();
            singleViewPlatform.MainView = window;

            // emulate MAUI behavior
            provider.InitializeMauiInitializeScopedService();
        }

        DataTemplates.Add(provider.GetRequiredService<ViewLocator>());

        base.OnFrameworkInitializationCompleted();

        // Usually, we don't want to block main UI thread.
        // But if it's required to start async services before we create any window,
        // then don't set any MainWindow, and simply call Show() on a new window later after async initialization. 
        await GlobalHost.StartAsync();
    }

    /// <summary>
    /// Note: The generic host approach is taken from maxkatz6 (a core contributor of Avalonia)
    /// https://github.com/AvaloniaUI/Avalonia/issues/5241#issuecomment-1792103733
    /// </summary>
    /// <returns></returns>
    private HostApplicationBuilder CreateHostBuilder()
    {
        // Alternatively, we can use Host.CreateDefaultBuilder, but this sample focuses on HostApplicationBuilder.
        var builder = Host.CreateApplicationBuilder(Environment.GetCommandLineArgs());

        foreach (var desc in _services!)
            builder.Services.Add(desc);

        return builder;
    }

}
