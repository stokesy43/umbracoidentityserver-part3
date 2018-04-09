using Microsoft.AspNet.Identity;
using Microsoft.Owin;
using Microsoft.Owin.Security.Cookies;
using Owin;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using Umbraco.Web;
using Umbraco.Web.Security.Identity;
using UmbracoIdentityServer.Part3.Client;

[assembly: OwinStartup("CustomOwinStartup", typeof(CustomOwinStartup))]

namespace UmbracoIdentityServer.Part3.Client
{
    public class CustomOwinStartup : UmbracoDefaultOwinStartup
    {
        /// <summary>
        /// Configures services to be created in the OWIN context (CreatePerOwinContext)
        /// </summary>
        /// <param name="app"/>
        protected override void ConfigureServices(IAppBuilder app)
        {
            base.ConfigureServices(app);

        }

        /// <summary>
        /// Configures middleware to be used (i.e. app.Use...)
        /// </summary>
        /// <param name="app"/>
        protected override void ConfigureMiddleware(IAppBuilder app)
        {
            //Ensure owin is configured for Umbraco back office authentication. If you have any front-end OWIN
            // cookie configuration, this must be declared after it.
            app
                .UseUmbracoBackOfficeCookieAuthentication(ApplicationContext, PipelineStage.Authenticate)
                .UseUmbracoBackOfficeExternalCookieAuthentication(ApplicationContext, PipelineStage.Authenticate);

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
                Provider = new CookieAuthenticationProvider()
            });

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            app.UseExternalSignInCookie(DefaultAuthenticationTypes.ExternalCookie);

            app.UseIdentityServerAuthentication("http://localhost:5000", "umbraco", "http://localhost:5001/");

            //Lasty we need to ensure that the preview Middleware is registered, this must come after
            // all of the authentication middleware:
            app.UseUmbracoPreviewAuthentication(ApplicationContext, PipelineStage.Authorize);

        }

    }
}
