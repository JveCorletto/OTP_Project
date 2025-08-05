using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace OTP_Project.Filters
{
    public class AutenticadoAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var isAuthenticated = context.HttpContext.Session.GetString("UsuarioEmail") != null;

            if (!isAuthenticated)
            {
                context.Result = new RedirectToActionResult("Login", "Auth", null);
            }
        }
    }
}