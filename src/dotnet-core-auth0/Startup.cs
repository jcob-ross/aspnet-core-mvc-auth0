namespace dotnet_core_auth0
{
  using Infrastructure;
  using Infrastructure.Authentication;
  using Microsoft.AspNetCore.Builder;
  using Microsoft.AspNetCore.Hosting;
  using Microsoft.Extensions.Configuration;
  using Microsoft.Extensions.DependencyInjection;
  using Microsoft.Extensions.Logging;

  public class Startup
  {
    public Startup(IHostingEnvironment env)
    {
      IConfigurationBuilder builder = new ConfigurationBuilder()
        .SetBasePath(env.ContentRootPath)
        .AddJsonFile("appsettings.json", true, true)
        .AddJsonFile($"appsettings.{env.EnvironmentName}.json", true)
        .AddEnvironmentVariables();
      Configuration = builder.Build();
    }

    public IConfigurationRoot Configuration { get; }

    public void ConfigureServices(IServiceCollection services)
    {
      services.AddMvc();
      services.AddOptions();
      services.Configure<Auth0Settings>(Configuration.GetSection("Auth0Settings"));
      services.Configure<AppSettings>(Configuration.GetSection("AppSettings"));

      var auth0Settings = new Auth0Settings
      {
        ClientId = Configuration["Auth0Settings:ClientId"],
        ClientSecret = Configuration["Auth0Settings:ClientSecret"],
        Domain = Configuration["Auth0Settings:Domain"]
      };

      services.AddAuth0(auth0Settings);
    }

    public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
    {
      loggerFactory.AddConsole(Configuration.GetSection("Logging"));
      loggerFactory.AddDebug();

      if (env.IsDevelopment())
      {
        app.UseDeveloperExceptionPage();
      }
      else
      {
        app.UseExceptionHandler("/Home/Error");
      }

      app.UseStaticFiles();

      app.UseAuth0();

      app.UseMvc(routes =>
                 {
                   routes.MapRoute("default", "{controller=Home}/{action=Index}/{id?}");
                 });
    }
  }
}