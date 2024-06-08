using LoginByIdentityCoreMVC.Models;
using LoginByIdentityCoreMVC.ViewModels;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System.Diagnostics;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace LoginByIdentityCoreMVC.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;

        public HomeController(ILogger<HomeController> logger, SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
        {
            _logger = logger;
            _signInManager = signInManager;
            _userManager = userManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }


        private async Task<bool> IsDeviceRemembered(ApplicationUser user)
        {
            var deviceClaim = (await _userManager.GetClaimsAsync(user)).FirstOrDefault(c => c.Type == "DeviceIdentifier");
            if (deviceClaim != null)
            {
                var currentDeviceIdentifier = GenerateUniqueIdentifier(HttpContext, user?.UserName); // Generate based on current request
                return deviceClaim.Value == currentDeviceIdentifier;
            }

            return false;
        }


        private string GenerateUniqueIdentifier(HttpContext httpContext, string? userName)
        {
            // Combine user agent and IP address to generate a unique identifier
            string userAgent = httpContext.Request.Headers["User-Agent"].ToString();
            string? ipAddress = httpContext.Connection.RemoteIpAddress?.ToString();

            string combinedData = $"{userAgent}{ipAddress}";

            using (var sha256 = SHA256.Create())
            {
                byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(combinedData));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }


        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> Verify2fa()
        {
            // Check if the device is remembered
            var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (user != null && await IsDeviceRemembered(user))
            {
                // Device is remembered, redirect to the home page or display a message
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }

            return View();
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Verify2fa(Verify2faViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _signInManager.GetTwoFactorAuthenticationUserAsync();
                if (user != null)
                {
                    // Check if the device is remembered
                    if (model.IsDeviceRemembered)
                    {
                        var deviceIdentifier = GenerateUniqueIdentifier(HttpContext, user.UserName); // Generate based on current request
                        await _userManager.AddClaimAsync(user, new Claim("DeviceIdentifier", deviceIdentifier));
                    }
                    var isValid2faCode = await _userManager.VerifyTwoFactorTokenAsync(user, "CustomTwoFactor", model.Code);
                    if (isValid2faCode)
                    {
                        await _signInManager.SignInAsync(user, model.IsDeviceRemembered);
                        return RedirectToAction(nameof(HomeController.Index), "Home");
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid two-factor code.");
                    }
                }
            }

            // If we reach here, something went wrong, redisplay the form
            return View(model);
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string? returnUrl = null)
        {
            // Validate the model and check credentials

            var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);

            if (result.Succeeded || result.RequiresTwoFactor)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {

                    if (result.RequiresTwoFactor && !await IsDeviceRemembered(user))
                    {
                        var get2faCode = await _userManager.GenerateTwoFactorTokenAsync(user, "CustomTwoFactor");
                        return RedirectToAction(nameof(Verify2fa));
                    }

                    return RedirectToAction(nameof(Index));
                }
            }
            ModelState.AddModelError(string.Empty, "Invalid login attempt.");
            return View();
            // Handle failed login logic
        }


        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                // Copy data from RegisterViewModel to IdentityUser
                var user = new ApplicationUser
                {
                    UserName = model.Email,
                    Email = model.Email,
                    TwoFactorEnabled = true
                };

                // Store user data in AspNetUsers database table
                var result = await _userManager.CreateAsync(user, model.Password);

                // If user is successfully created, sign-in the user using
                // SignInManager and redirect to index action of HomeController
                if (result.Succeeded)
                {
                    return RedirectToAction(nameof(Login));
                }

                // If there are any errors, add them to the ModelState object
                // which will be displayed by the validation summary tag helper
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }
            }

            return View(model);
        }

        [HttpPost]
        public IActionResult Register2([FromBody]List<RegisterViewModel> model)
        {
            return Content(JsonConvert.SerializeObject(model));
        }

        }
}