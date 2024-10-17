using System;
using System.Globalization;
using System.Threading.Tasks;
using System.Web.Http;
using System.Web.Mvc;
using Autofac;
using Autofac.Extensions.DependencyInjection;
using Autofac.Integration.Mvc;
using Autofac.Integration.WebApi;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Owin;
using Microsoft.Owin.Host.SystemWeb;
using Microsoft.Owin.Security.Cookies;
using OpenIddict.Abstractions;
using OpenIddict.Client.Owin;
using OpenIddict.Sandbox.AspNet.Server.Models;
using OpenIddict.Server.Owin;
using OpenIddict.Validation.Owin;
using Owin;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Server.OpenIddictServerEvents;

[assembly: OwinStartup(typeof(OpenIddict.Sandbox.AspNet.Server.Startup))]
namespace OpenIddict.Sandbox.AspNet.Server;

public class Startup
{
    public void Configuration(IAppBuilder app)
    {
        var services = new ServiceCollection();

        services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the Entity Framework 6.x stores and models.
                // Note: call ReplaceDefaultEntities() to replace the default OpenIddict entities.
                options.UseEntityFramework()
                       .UseDbContext<ApplicationDbContext>();

                // Developers who prefer using MongoDB can remove the previous lines
                // and configure OpenIddict to use the specified MongoDB database:
                // options.UseMongoDb()
                //        .UseDatabase(new MongoClient().GetDatabase("openiddict"));
            })

            // Register the OpenIddict client components.
            .AddClient(options =>
            {
                // Note: this sample uses the code flow, but you can enable the other flows if necessary.
                options.AllowAuthorizationCodeFlow();

                // Register the signing and encryption credentials used to protect
                // sensitive data like the state tokens produced by OpenIddict.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Register the OWIN host and configure the OWIN-specific options.
                options.UseOwin()
                       .EnableRedirectionEndpointPassthrough()
                       .SetCookieManager(new SystemWebCookieManager());

                // Register the System.Net.Http integration and use the identity of the current
                // assembly as a more specific user agent, which can be useful when dealing with
                // providers that use the user agent as a way to throttle requests (e.g Reddit).
                options.UseSystemNetHttp()
                       .SetProductInformation(typeof(Startup).Assembly);

                // Register the Web providers integrations.
                //
                // Note: to mitigate mix-up attacks, it's recommended to use a unique redirection endpoint
                // URI per provider, unless all the registered providers support returning a special "iss"
                // parameter containing their URL as part of authorization responses. For more information,
                // see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#section-4.4.
                options.UseWebProviders()
                       .AddGitHub(options =>
                       {
                           options.SetClientId("c4ade52327b01ddacff3")
                                  .SetClientSecret("da6bed851b75e317bf6b2cb67013679d9467c122")
                                  .SetRedirectUri("callback/login/github");
                       })
                       .AddMicrosoft(options =>
                       {
                           options
                               .SetClientId("e622a0e5-f3e8-4998-b4e1-35f45e9b18cd") // application (client) id
                               .SetClientSecret("_8x8Q~fc7GxwbieK04mL2tQuzrlqMU_yPTd5rawD") // generated secret from azure portal
                               .SetRedirectUri("/callback/login/microsoft");
                       });

            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                //options.SetIssuer(new Uri("https://vsr1d2md-44349.euw.devtunnels.ms/"));

                // Enable the authorization, device, introspection,
                // logout, token, userinfo and verification endpoints.
                options.SetAuthorizationEndpointUris("connect/authorize")
                       .SetDeviceEndpointUris("connect/device")
                       .SetIntrospectionEndpointUris("connect/introspect")
                       .SetLogoutEndpointUris("connect/logout")
                       .SetTokenEndpointUris("connect/token")
                       .SetUserinfoEndpointUris("connect/userinfo")
                       .SetVerificationEndpointUris("connect/verify");

                // Note: this sample uses the code, device code, password and refresh token flows, but you
                // can enable the other flows if you need to support implicit or client credentials.
                options.AllowAuthorizationCodeFlow()
                       .AllowDeviceCodeFlow()
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                // Mark the "email", "profile", "roles" and "demo_api" scopes as supported scopes.
                options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, "demo_api");

                // Register the signing and encryption credentials.
                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                // Force client applications to use Proof Key for Code Exchange (PKCE).
                options.RequireProofKeyForCodeExchange();

                // Register the OWIN host and configure the OWIN-specific options.
                options.UseOwin()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough()
                       .EnableVerificationEndpointPassthrough();

                options.AddEventHandler<ValidateTokenContext>(bldr =>
                {
                    bldr.UseInlineHandler(vtc =>
                    {
                        if(vtc.TokenTypeHint == TokenTypeHints.RefreshToken)
                        {
                            
                        }

                        return default;
                    });

                });
            })

            // Register the OpenIddict validation components.
            .AddValidation(options =>
            {
                // Import the configuration from the local OpenIddict server instance.
                options.UseLocalServer();

                // Register the OWIN host.
                options.UseOwin();
            });

        // Create a new Autofac container and import the OpenIddict services.
        var builder = new ContainerBuilder();
        builder.Populate(services);

        // Register the MVC controllers.
        builder.RegisterControllers(typeof(Startup).Assembly);

        // Register the Web API controllers.
        builder.RegisterApiControllers(typeof(Startup).Assembly);

        var container = builder.Build();

        // Register the Autofac scope injector middleware.
        app.UseAutofacLifetimeScopeInjector(container);

        // Register the Entity Framework context and the user/sign-in managers used by ASP.NET Identity.
        app.CreatePerOwinContext(ApplicationDbContext.Create);
        app.CreatePerOwinContext<ApplicationUserManager>(ApplicationUserManager.Create);
        app.CreatePerOwinContext<ApplicationSignInManager>(ApplicationSignInManager.Create);

        // Register the cookie middleware used by ASP.NET Identity.
        app.UseCookieAuthentication(new CookieAuthenticationOptions
        {
            AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
            LoginPath = new PathString("/Account/Login"),
            Provider = new CookieAuthenticationProvider
            {
                OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, ApplicationUser>(
                    validateInterval: TimeSpan.FromMinutes(30),
                    regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
            }
        });

        app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);
        app.UseTwoFactorSignInCookie(DefaultAuthenticationTypes.TwoFactorCookie, TimeSpan.FromMinutes(5));
        app.UseTwoFactorRememberBrowserCookie(DefaultAuthenticationTypes.TwoFactorRememberBrowserCookie);

        // Register the OpenIddict middleware.
        app.UseMiddlewareFromContainer<OpenIddictClientOwinMiddleware>();
        app.UseMiddlewareFromContainer<OpenIddictServerOwinMiddleware>();
        app.UseMiddlewareFromContainer<OpenIddictValidationOwinMiddleware>();

        // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances.
        DependencyResolver.SetResolver(new AutofacDependencyResolver(container));

        // Configure ASP.NET MVC 5.2 to use Autofac when activating controller instances
        // and infer the Web API routes using the HTTP attributes used in the controllers.
        var configuration = new HttpConfiguration
        {
            DependencyResolver = new AutofacWebApiDependencyResolver(container)
        };

        configuration.MapHttpAttributeRoutes();
        configuration.SuppressDefaultHostAuthentication();

        // Register the Autofac Web API integration and Web API middleware.
        app.UseAutofacWebApi(configuration);
        app.UseWebApi(configuration);

        // Seed the database with the sample client using the OpenIddict application manager.
        // Note: in a real world application, this step should be part of a setup script.
        Task.Run(async delegate
        {
            await using var scope = container.BeginLifetimeScope();

            var context = scope.Resolve<ApplicationDbContext>();
            context.Database.CreateIfNotExists();

            var manager = scope.Resolve<IOpenIddictApplicationManager>();

            var mvcd = new OpenIddictApplicationDescriptor
            {
                ApplicationType = ApplicationTypes.Web,
                ClientId = "mvc",
                ClientSecret = "901564A5-E7FE-42CB-B10D-61EF6A8F3654",
                ClientType = ClientTypes.Confidential,
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "MVC client application",
                RedirectUris =
                    {
                        new Uri("https://localhost:44349/callback/login/local")
                    },
                PostLogoutRedirectUris =
                    {
                        new Uri("https://localhost:44349/logout/local")
                    },
                Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
            };
            var mvc = await manager.FindByClientIdAsync("mvc");
            if (mvc is null)
            {
                await manager.CreateAsync(mvcd);
            }
            else
            {
                await manager.UpdateAsync(mvc, mvcd);
            }

            var mauid = new OpenIddictApplicationDescriptor
            {
                ApplicationType = ApplicationTypes.Native,
                ClientId = "avalonia",
                ClientType = ClientTypes.Public,
                ConsentType = ConsentTypes.Implicit,
                DisplayName = "Avalonia client application",
                DisplayNames =
                    {
                        [CultureInfo.GetCultureInfo("fr-FR")] = "Application cliente avalonia"
                    },
                PostLogoutRedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.avalonia.client:/callback/logout/local")
                    },
                RedirectUris =
                    {
                        new Uri("com.openiddict.sandbox.avalonia.client:/callback/login/local")
                    },
                Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles,
                        Permissions.Prefixes.Scope + "demo_api"
                    },
                Requirements =
                    {
                        Requirements.Features.ProofKeyForCodeExchange
                    }
            };
            var maui = await manager.FindByClientIdAsync("avalonia");
            if (maui is null)
            {
                await manager.CreateAsync(mauid);
            }
            else
            {
                await manager.UpdateAsync(maui, mauid);
            }

            var mvc2d = new OpenIddictApplicationDescriptor
            {
                ClientId = "mvc2",
                ConsentType = ConsentTypes.Explicit,
                DisplayName = "Mvc browser client application",
                ClientType = ClientTypes.Public,
                PostLogoutRedirectUris =
                    {
                        new Uri("https://localhost:44349/logout/local2")
                    },
                RedirectUris =
                    {
                        new Uri("https://localhost:44349/callback/login/local2")
                    },
                Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Logout,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                Requirements =
                    {
                        //Requirements.Features.ProofKeyForCodeExchange
                    }
            };
            var mvc2 = await manager.FindByClientIdAsync("mvc2");

            if (mvc2 is null)
                await manager.CreateAsync(mvc2d);
            else
                await manager.UpdateAsync(mvc2, mvc2d);


            var flrd = new OpenIddictApplicationDescriptor
            {
                ClientId = "mobileapp",
                ClientSecret = "secret",
                DisplayName = "Mobile App",
                RedirectUris = { new Uri("https://localhost:44349/account/callback") },
                ClientType = OpenIddictConstants.ClientTypes.Confidential,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Logout,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                },
                Properties = { },
            };
            var flr = await manager.FindByClientIdAsync("mobileapp");

            if (flr is null)
                await manager.CreateAsync(flrd);
            else
                await manager.UpdateAsync(flr, flrd);

            var prtld = new OpenIddictApplicationDescriptor
            {
                ClientId = "webapp",
                // A client secret cannot be associated with a public application.
                DisplayName = "Web App",
                RedirectUris = { new Uri("https://localhost:44300/Account/Callback") },
                ClientType = OpenIddictConstants.ClientTypes.Public,
                ConsentType = OpenIddictConstants.ConsentTypes.Implicit,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Logout,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,
                    OpenIddictConstants.Permissions.GrantTypes.Password,
                    OpenIddictConstants.Permissions.GrantTypes.RefreshToken,
                    OpenIddictConstants.Permissions.ResponseTypes.Code,
                    OpenIddictConstants.Permissions.Scopes.Email,
                    OpenIddictConstants.Permissions.Scopes.Profile,
                    OpenIddictConstants.Permissions.Scopes.Roles
                },
                Requirements =
                {
                    OpenIddictConstants.Requirements.Features.ProofKeyForCodeExchange
                },
                Properties = { },
            };
            var prtl = await manager.FindByClientIdAsync("webapp");

            if (prtl is null)
                await manager.CreateAsync(prtld);
            else
                await manager.UpdateAsync(prtl, prtld);


            if (await manager.FindByClientIdAsync("postman") is null)
            {
                await manager.CreateAsync(new OpenIddictApplicationDescriptor
                {
                    ApplicationType = ApplicationTypes.Native,
                    ClientId = "postman",
                    ClientType = ClientTypes.Public,
                    ConsentType = ConsentTypes.Systematic,
                    DisplayName = "Postman",
                    RedirectUris =
                    {
                        new Uri("https://oauth.pstmn.io/v1/callback")
                    },
                    Permissions =
                    {
                        Permissions.Endpoints.Authorization,
                        Permissions.Endpoints.Device,
                        Permissions.Endpoints.Token,
                        Permissions.GrantTypes.AuthorizationCode,
                        Permissions.GrantTypes.DeviceCode,
                        Permissions.GrantTypes.Password,
                        Permissions.GrantTypes.RefreshToken,
                        Permissions.ResponseTypes.Code,
                        Permissions.Scopes.Email,
                        Permissions.Scopes.Profile,
                        Permissions.Scopes.Roles
                    },
                    Settings =
                    {
                        // Use a shorter access token lifetime for tokens issued to the Postman application.
                        [Settings.TokenLifetimes.AccessToken] = TimeSpan.FromMinutes(10).ToString("c", CultureInfo.InvariantCulture)
                    }
                });
            }
        }).GetAwaiter().GetResult();
    }
}
