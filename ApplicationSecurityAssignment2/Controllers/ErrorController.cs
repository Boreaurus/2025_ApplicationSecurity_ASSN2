using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace ApplicationSecurityAssignment2.Controllers
{
    public class ErrorController : Controller
    {
        // Handles /Error (500 etc)
        [Route("Error")]
        public IActionResult Error()
        {
            var feature = HttpContext.Features.Get<IExceptionHandlerPathFeature>();
            ViewBag.Path = feature?.Path;
            ViewBag.ExceptionMessage = feature?.Error?.Message; // don't show this in prod UI
            return View("Error");
        }

        // Handles /Error/{statusCode} (404/403/etc)
        [Route("Error/{statusCode:int}")]
        public IActionResult HttpStatusCodeHandler(int statusCode)
        {
            ViewBag.StatusCode = statusCode;

            // Optionally capture original path for status codes
            var statusFeature = HttpContext.Features.Get<IStatusCodeReExecuteFeature>();
            ViewBag.OriginalPath = statusFeature?.OriginalPath;

            return statusCode switch
            {
                404 => View("NotFound"),
                403 => View("Forbidden"),
                _ => View("HttpStatusCode")
            };
        }
    }
}
