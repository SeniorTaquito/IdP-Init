using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;

namespace MvcApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Callback(string code)
        {
            var id_token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik56UkVOa0pET0VVM1FUZzFOall4TXpsR05VWXlNalUxTVROQk1FSTFOVE00TmpCR016UTRNdyJ9.eyJuaWNrbmFtZSI6ImRhbi5jb2hlbiIsIm5hbWUiOiJkYW4uY29oZW5AYXV0aDAuY29tIiwicGljdHVyZSI6Imh0dHBzOi8vcy5ncmF2YXRhci5jb20vYXZhdGFyLzg5MDJiZDRmZTUzODFkYjY5MjE4MWYxZTE4MjFiODM0P3M9NDgwJnI9cGcmZD1odHRwcyUzQSUyRiUyRmNkbi5hdXRoMC5jb20lMkZhdmF0YXJzJTJGZGEucG5nIiwidXBkYXRlZF9hdCI6IjIwMjAtMTAtMThUMTY6MTU6MDUuNDc5WiIsImlzcyI6Imh0dHBzOi8vZGFuY28uYXV0aDAuY29tLyIsInN1YiI6ImF1dGgwfDVkOTY0OWZhMzU5OTIyMGM1OGE2ZmM1YiIsImF1ZCI6Ilh5d3NHaTJYRzNoTDFGNndMZzZiNXdBWGlrSXJ5TGF2IiwiaWF0IjoxNjAzMDM3NzA3LCJleHAiOjE2MDMwNzM3MDd9.BuWTuh9j_aOcyDT0035vcQZfBBoC735AVl8HJORlX-xqd_sjeWB4VMvsu7Mgem4l5wfanrliq8ZThB2Nsc696K6ENHGpMMrIb0huaPQC1o7bbrsUteIPozcisOLrZQS7B7fD7PSORIOKAHpeVeSeIW2S500-2F4Kp24urfoMUDyWELk71pN28owOWU3znfPZYQWADMuRPrY-BhJf1YMUIcnTUJ9AnqFDO7TwC_qc0wheqV_ka3Rl4nDdeeG3H44Ud39YYuiqDnofSHh2UphBcRDQKuh2CxXx_GTtYReinhMSthXHHGcwv_iZ_fo0IDFFpqlGfRxs6xJr0bv8YX1KNA";
            //decode token and add claims to a dictionary
            var tokenHandler = new JwtSecurityTokenHandler();
            var jsonToken = tokenHandler.ReadJwtToken(id_token);

            var claims = new Dictionary<string, string>();

            foreach (var claim in jsonToken.Claims)
            {
                claims.Add(claim.Type, claim.Value);
            }

            //load claims into the ClaimsIdentity object
            ClaimsIdentity claimIdentity = new ClaimsIdentity(new[] {
                new Claim( ClaimTypes.NameIdentifier, claims["nickname"], ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer),
                new Claim( ClaimTypes.Name, claims["nickname"], ClaimValueTypes.String, ClaimsIdentity.DefaultIssuer),
                new Claim("name", claims["name"], ClaimValueTypes.String),
                new Claim("picture", claims["picture"], ClaimValueTypes.String),
                new Claim("iss", claims["iss"], ClaimValueTypes.String),
                new Claim("user_id", claims["sub"], ClaimValueTypes.String),
                new Claim("id_token", id_token, ClaimValueTypes.String)
            },
            CookieAuthenticationDefaults.AuthenticationType,
            ClaimsIdentity.DefaultNameClaimType,
            ClaimsIdentity.DefaultRoleClaimType
            );

            //get the authentication manager 
            var authManager = HttpContext.GetOwinContext().Authentication;

            //remove the asp.net session cookie
            authManager.SignOut(CookieAuthenticationDefaults.AuthenticationType);

            //log the user out of Auth0 (configured in mideelware)
            authManager.SignOut("Auth0");

            //sign the user in using the  customClaimsIdeneity object
            authManager.SignIn(new AuthenticationProperties { }, claimIdentity);

            return RedirectToAction("Index", "Home");
        }

        public ActionResult Login(string returnUrl)
        {
            HttpContext.GetOwinContext().Authentication.Challenge(new AuthenticationProperties
                {
                    RedirectUri = returnUrl ?? Url.Action("Index", "Home")
                },
                "Auth0");
            return new HttpUnauthorizedResult();
        }

        [Authorize]
        public void Logout()
        {
            HttpContext.GetOwinContext().Authentication.SignOut(CookieAuthenticationDefaults.AuthenticationType);
            HttpContext.GetOwinContext().Authentication.SignOut("Auth0");
        }

        [Authorize]
        public ActionResult Tokens()
        {
            var claimsIdentity = User.Identity as ClaimsIdentity;

            ViewBag.AccessToken = claimsIdentity?.FindFirst(c => c.Type == "access_token")?.Value;
            ViewBag.IdToken = claimsIdentity?.FindFirst(c => c.Type == "id_token")?.Value;

            return View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            return View();
        }
    }
}