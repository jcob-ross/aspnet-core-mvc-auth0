namespace dotnet_core_auth0.Controllers
{
  using Microsoft.AspNetCore.Authorization;
  using Microsoft.AspNetCore.Mvc;

  public class HomeController : Controller
  {
    public IActionResult Index()
    {
      return View();
    }

    public IActionResult Api()
    {
      return View();
    }

    [Authorize(ActiveAuthenticationSchemes = "Cookies")]
    public IActionResult Profile()
    {
      return View(User.Claims);
    }

    public IActionResult Error()
    {
      return View();
    }
  }
}