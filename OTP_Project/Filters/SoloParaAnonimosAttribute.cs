using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace OTP_Project.Filters
{
    public class SoloParaAnonimosAttribute : ActionFilterAttribute
    {
        public override void OnActionExecuting(ActionExecutingContext context)
        {
            var session = context.HttpContext.Session.GetString("UsuarioEmail");
            if (!string.IsNullOrEmpty(session))
            {
                // Si ya hay sesión, redirige al dashboard u otra página
                context.Result = new RedirectToActionResult("Index", "Home", null);
            }
        }
    }
}