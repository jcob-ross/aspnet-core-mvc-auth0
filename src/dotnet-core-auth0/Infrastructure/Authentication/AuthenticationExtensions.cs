namespace dotnet_core_auth0.Infrastructure.Authentication
{
  using System;
  using System.Security.Claims;
  using System.Security.Cryptography;
  using System.Threading.Tasks;
  using Microsoft.AspNetCore.Authentication;
  using Microsoft.AspNetCore.Authentication.Cookies;
  using Microsoft.AspNetCore.Authentication.OpenIdConnect;
  using Microsoft.AspNetCore.Builder;
  using Microsoft.AspNetCore.Http;
  using Microsoft.AspNetCore.Http.Authentication;
  using Microsoft.Extensions.DependencyInjection;
  using Microsoft.Extensions.Logging;
  using Microsoft.Extensions.Options;
  using Microsoft.IdentityModel.Protocols.OpenIdConnect;

  public static class AuthenticationExtensions
  {
    private static ILogger _logger;

    private static readonly RandomNumberGenerator CryptoRandom = RandomNumberGenerator.Create();
    private const string CorrelationPrefix = ".AspNetCore.Correlation.";
    private const string CorrelationProperty = ".xsrf";
    private const string CorrelationMarker = "N";
    private const string NonceProperty = "N";
    private const string ProtocolScheme = "http://";

    public static void AddAuth0(this IServiceCollection services, Auth0Settings settings)
    {
      if (null == services)
        throw new ArgumentNullException(nameof(services));
      if (null == settings)
        throw new ArgumentNullException(nameof(settings));
      
      services.AddAuthentication(options => 
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme);

      services.Configure<OpenIdConnectOptions>(options =>
      {
        options.RequireHttpsMetadata = false;

        options.AutomaticAuthenticate = true;
        options.AutomaticChallenge = false;

        options.AuthenticationScheme = "Auth0";
        options.ResponseType = OpenIdConnectResponseType.Code;

        options.Authority = $"{ProtocolScheme}{settings.Domain}";
        options.ClientId = settings.ClientId;
        options.ClientSecret = settings.ClientSecret;
        options.CallbackPath = new PathString("/signin-auth0");
        options.ClaimsIssuer = "Auth0";
        options.PostLogoutRedirectUri = new PathString("/Home/Api");

        options.Events = new OpenIdConnectEvents()
        {
          OnTokenValidated = validatedContext =>
          {
            var identity = validatedContext.Ticket.Principal.Identity as ClaimsIdentity;
            if (identity != null)
            {
              // User.Identity.Name should always have a value
              if (!validatedContext.Ticket.Principal.HasClaim(c => c.Type == ClaimTypes.Name) &&
                              identity.HasClaim(c => c.Type == "name"))
                identity.AddClaim(new Claim(ClaimTypes.Name, identity.FindFirst("name").Value));
            }
            return Task.FromResult(true);
          },
          OnRedirectToIdentityProviderForSignOut = redirectContext =>
          {
            _logger.LogDebug("Signing out and redirecting to Auth0.");

            redirectContext.HandleResponse();
            redirectContext.HttpContext.Response.Redirect($"{ProtocolScheme}{settings.Domain}/v2/logout?returnTo={redirectContext.ProtocolMessage.RedirectUri}");
            return Task.FromResult(true);
          },

          OnAuthenticationFailed = failedContext =>
          {
            _logger.LogError("Authentication failed: " + failedContext.Exception.Message);
            return Task.FromResult(true);
          },
          OnRemoteFailure = notification =>
          {
            _logger.LogError("Remote error: " + notification.Failure.Message);
            return Task.FromResult(true);
          }
        };
      });
    }

    public static void UseAuth0(this IApplicationBuilder app)
    {
      var loggerFactory = app.ApplicationServices.GetService(typeof(ILoggerFactory)) as ILoggerFactory;
      _logger = loggerFactory.CreateLogger("Auth0");

      app.UseCookieAuthentication(new CookieAuthenticationOptions
      {
        AutomaticAuthenticate = true,
        AutomaticChallenge = true,

        LoginPath = new PathString("/Account/Login"),
        LogoutPath = new PathString("/Account/Logout")
      });

      var options = app.ApplicationServices.GetRequiredService<IOptions<OpenIdConnectOptions>>();
      app.UseOpenIdConnectAuthentication(options.Value);
    }

    /// <summary>
    ///   Creates nonce and appends it to cookie
    /// </summary>
    private static void GenerateCorrelationId(HttpContext context, OpenIdConnectOptions options, AuthenticationProperties properties)
    {
      if (properties == null)
        throw new ArgumentNullException(nameof(properties));

      var bytes = new byte[32];
      CryptoRandom.GetBytes(bytes);
      var correlationId = Base64UrlTextEncoder.Encode(bytes);


      var cookieOptions = new CookieOptions
      {
        HttpOnly = true,
        Secure = context.Request.IsHttps,
        Expires = properties.ExpiresUtc
      };

      properties.Items[CorrelationProperty] = correlationId;
      var cookieName = CorrelationPrefix + options.AuthenticationScheme + "." + correlationId;
      
      context.Response.Cookies.Append(cookieName, CorrelationMarker, cookieOptions);
    }

    /// <summary>
    ///   Creates redirect uri for <see cref="GenerateLockContext"/>
    /// </summary>
    private static string BuildRedirectUri(HttpRequest request, PathString redirectPath)
    {
      return request.Scheme + "://" + request.Host + request.PathBase + redirectPath;
    }

    /// <summary>
    ///   Creates context for Auth0 Lock (nonce, state, redirect uri etc.)
    /// </summary>
    public static LockContext GenerateLockContext(this HttpContext httpContext, OpenIdConnectOptions options, string returnUrl = null)
    {
      var lockContext = new LockContext();

      // Set the options
      lockContext.ClientId = options.ClientId;

      // retrieve the domain from the authority
      Uri authorityUri;
      if (Uri.TryCreate(options.Authority, UriKind.Absolute, out authorityUri))
      {
        lockContext.Domain = authorityUri.Host;
      }

      // Set the redirect
      string callbackUrl = BuildRedirectUri(httpContext.Request, options.CallbackPath);
      lockContext.CallbackUrl = callbackUrl;

      // Add the nonce.
      var nonce = options.ProtocolValidator.GenerateNonce();
      httpContext.Response.Cookies.Append(
          OpenIdConnectDefaults.CookieNoncePrefix + options.StringDataFormat.Protect(nonce),
          NonceProperty,
          new CookieOptions
          {
            HttpOnly = true,
            Secure = httpContext.Request.IsHttps,
            Expires = DateTime.UtcNow + options.ProtocolValidator.NonceLifetime
          });
      lockContext.Nonce = nonce;

      //generate nonce/state for /account/login so it can be validated after receiving the code

      var properties = new AuthenticationProperties()
      {
        ExpiresUtc = options.SystemClock.UtcNow.Add(options.RemoteAuthenticationTimeout),
        RedirectUri = returnUrl ?? "/"
      };
      properties.Items[OpenIdConnectDefaults.RedirectUriForCodePropertiesKey] = callbackUrl;
      GenerateCorrelationId(httpContext, options, properties);

      // Generate State
      lockContext.State = Uri.EscapeDataString(options.StateDataFormat.Protect(properties));

      // return the Lock context
      return lockContext;
    }
  }
}