namespace dotnet_core_auth0.Controllers.Apis
{
  using Microsoft.AspNetCore.Authentication.Cookies;
  using Microsoft.AspNetCore.Authorization;
  using Microsoft.AspNetCore.Mvc;
  using System.Linq;

  public class SampleApiController : Controller
  {
    [HttpGet]
    [Route("api/ping")]
    public IActionResult Ping()
    {
      return Json(new
      {
        message = "You accessed an unprotected endpoint."
      });
    }

    [HttpGet]
    [Authorize(ActiveAuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
    [Route("api/secured/ping")]
    public IActionResult SecuredPing()
    { 
      return Json(new
      {
        message = "You accessed the protected endpoint, here are your claims:",
        claims = User.Claims.Select(c => new { c.Type, c.Value })
      });
    }
  }
}