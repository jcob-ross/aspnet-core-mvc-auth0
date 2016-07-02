namespace dotnet_core_auth0.Controllers
{
  using System.Threading.Tasks;
  using Infrastructure.Authentication;
  using Microsoft.AspNetCore.Authentication.Cookies;
  using Microsoft.AspNetCore.Builder;
  using Microsoft.AspNetCore.Mvc;
  using Microsoft.Extensions.Logging;
  using Microsoft.Extensions.Options;

  public class AccountController : Controller
  {
    private readonly IOptions<OpenIdConnectOptions> _options;
    private readonly ILogger<AccountController> _log;

    public AccountController(IOptions<OpenIdConnectOptions> options, ILogger<AccountController> log)
    {
      _options = options;
      _log = log;
    }

    public IActionResult Login(string returnUrl = null)
    {
      _log.LogDebug("Creating login view with return uri {returnUrl}", returnUrl ?? "-none-");
      var lockContext = HttpContext.GenerateLockContext(_options.Value, returnUrl);
      
      return View(lockContext);
    }

    [HttpPost]
    public async Task<IActionResult> Logout()
    {
      if (HttpContext.User.Identity.IsAuthenticated)
      {
        _log.LogDebug("Logging out user {user}", HttpContext.User.Identity.Name);
        await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
      }

      var redirectPath = _options.Value.PostLogoutRedirectUri;
      return Redirect($"{Request.Scheme}://{Request.Host}{Request.PathBase}{redirectPath}");
    }
  }
}