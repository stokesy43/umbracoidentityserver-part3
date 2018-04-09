using IdentityModel;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Umbraco.Core;
using Umbraco.Web;
using Umbraco.Web.Mvc;

namespace UmbracoIdentityServer.Part3.Client.Controllers
{
    public class AccountController : SurfaceController
    {
        [HttpGet]
        [AllowAnonymous]
        public ActionResult ExternalLogin(string provider, string returnUrl = null)
        {
            if (provider.IsNullOrWhiteSpace() && returnUrl.IsNullOrWhiteSpace())
            {
                return Redirect("/account");
            }

            if (returnUrl.IsNullOrWhiteSpace())
            {
                returnUrl = Request.RawUrl;
            }

            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
            {
                RedirectUri = Url.SurfaceAction<AccountController>("ExternalLoginCallback", new { ReturnUrl = returnUrl })
            }, provider);

            return new HttpUnauthorizedResult();
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl)
        {
            // First get the authentication information from identity server
            var loginInfo = await HttpContext.GetOwinContext().Authentication.GetExternalLoginInfoAsync();

            if (loginInfo == null)
            {
                //go home, invalid callback
                return RedirectToLocal(returnUrl);
            }

            // Get the relevant claims from the external identity
            var email = loginInfo.ExternalIdentity.Claims.First(c => c.Type == JwtClaimTypes.Email).Value;
            var name = loginInfo.ExternalIdentity.Claims.First(c => c.Type == JwtClaimTypes.Name).Value;
            var role = loginInfo.ExternalIdentity.Claims.First(c => c.Type == JwtClaimTypes.Role).Value;
            
            // Sign out externally
            HttpContext.GetOwinContext().Authentication.SignOut(DefaultAuthenticationTypes.ExternalCookie);

            // Create a local claims identity copying the claims provided from the external provider
            var claims = new List<Claim>
            {
                new Claim(JwtClaimTypes.Email, email),
                new Claim(JwtClaimTypes.Name, name),
                new Claim(JwtClaimTypes.Role, role),
            };

            var id = new ClaimsIdentity(DefaultAuthenticationTypes.ApplicationCookie, JwtClaimTypes.Email, JwtClaimTypes.Role);
            id.AddClaims(claims);

            // Sign in locally
            HttpContext.GetOwinContext().Authentication.SignIn(new AuthenticationProperties() { IsPersistent = false }, id);
            
            return RedirectToLocal(returnUrl);

        }

        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            return Redirect("/");
        }

    }
}