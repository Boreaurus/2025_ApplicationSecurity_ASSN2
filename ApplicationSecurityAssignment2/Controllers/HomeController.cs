using ApplicationSecurityAssignment2.Models;
using ApplicationSecurityAssignment2.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.CodeAnalysis.FlowAnalysis.DataFlow;
using Microsoft.Data.SqlClient;
using System.Diagnostics;

namespace ApplicationSecurityAssignment2.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AesEncryptionService _aes;

        public HomeController(
            ILogger<HomeController> logger,
            UserManager<ApplicationUser> userManager,
            AesEncryptionService aes)
        {
            _logger = logger;
            _userManager = userManager;
            _aes = aes;
        }

        public async Task<IActionResult> Index()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null)
                return Challenge();

            string? decryptedCard = null;
            if (!string.IsNullOrWhiteSpace(user.EncryptedCreditCard) &&
                !string.IsNullOrWhiteSpace(user.CreditCardIV))
            {
                decryptedCard = _aes.Decrypt(user.EncryptedCreditCard, user.CreditCardIV);
            }

            var vm = new ProfileViewModel
            {
                Email = user.Email ?? "",
                FirstName = user.FirstName,
                LastName = user.LastName,
                PhoneNumber = user.PhoneNumber ?? "",
                BillingAddress = user.BillingAddress,
                ShippingAddress = user.ShippingAddress,
                CreditCardNo = decryptedCard ?? "",
                PhotoFileName = user.PhotoFileName
            };

            return View(vm);
        }

        [AllowAnonymous]
        public IActionResult Privacy()
        {
            throw new Exception("Simulated error from Privacy");
        }

        [AllowAnonymous]
        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            });
        }
    }

    public class ProfileViewModel
    {
        public string Email { get; set; } = "";
        public string FirstName { get; set; } = "";
        public string LastName { get; set; } = "";
        public string PhoneNumber { get; set; } = "";
        public string BillingAddress { get; set; } = "";
        public string ShippingAddress { get; set; } = "";
        public string CreditCardNo { get; set; } = "";
        public string? PhotoFileName { get; set; }
    }
}
