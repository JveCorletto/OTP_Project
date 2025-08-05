using OTP_Project.Data;
using OTP_Project.Models;
using OTP_Project.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using OTP_Project.Filters;

namespace OTP_Project.Controllers
{
    public class AuthController : Controller
    {
        private readonly ApplicationDbContext _db;
        private readonly EmailService _emailService;
        private readonly PasswordHasher<Usuarios> _hasher;

        public AuthController(ApplicationDbContext db, PasswordHasher<Usuarios> hasher, EmailService emailService)
        {
            _db = db;
            _hasher = hasher;
            _emailService = emailService;
        }

        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult Registro()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> Registro(string Email, string Password)
        {
            // Verificar si ya existe el usuario
            if (_db.Usuarios.Any(u => u.Email == Email))
            {
                ModelState.AddModelError(string.Empty, "Este correo ya está registrado.");
                return View();
            }

            var otp = new Random().Next(100000, 999999).ToString();
            var expira = DateTime.Now.AddMinutes(5);

            await _emailService.EnviarOTP(Email, otp);

            TempData["OTP"] = otp;
            TempData["OTPExpira"] = expira.ToString();
            TempData["Email"] = Email;
            TempData["Password"] = Password;

            return RedirectToAction("VerificarOTP");
        }

        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult VerificarOTP()
        {
            return View();
        }


        [HttpPost]
        public IActionResult VerificarOTP(string codigo)
        {
            string otpGuardado = TempData["OTP"]?.ToString();
            string email = TempData["Email"]?.ToString();
            string password = TempData["Password"]?.ToString();
            DateTime expira = DateTime.Parse(TempData["OTPExpira"]?.ToString() ?? DateTime.MinValue.ToString());

            if (codigo == otpGuardado && DateTime.Now < expira)
            {
                var user = new Usuarios
                {
                    Email = email,
                    PasswordHash = _hasher.HashPassword(null, password),
                    Autenticacion2FAActiva = false
                };

                _db.Usuarios.Add(user);
                _db.SaveChanges();

                return Content("✔️ Usuario registrado correctamente. Ahora podés configurar el Authenticator.");
            }

            return Content("❌ Código incorrecto o expirado.");
        }


        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Login(string email, string password)
        {
            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);

            if (user == null)
            {
                ViewBag.Error = "Usuario no encontrado.";
                return View();
            }

            var resultado = _hasher.VerifyHashedPassword(user, user.PasswordHash, password);

            if (resultado == PasswordVerificationResult.Success)
            {
                HttpContext.Session.SetString("UsuarioEmail", user.Email);
                return RedirectToAction("Index", "Home");
            }

            ViewBag.Error = "Contraseña incorrecta.";
            return View();
        }

        [HttpGet]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Auth");
        }
    }
}