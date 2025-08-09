using OTP_Project.Data;
using OTP_Project.Models;
using OTP_Project.Filters;
using OTP_Project.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;

namespace OTP_Project.Controllers
{
    public class AuthController : Controller
    {
        private readonly TOTPService _totpService;
        private readonly EmailService _emailService;

        private readonly ApplicationDbContext _db;
        private readonly PasswordHasher<Usuarios> _hasher;

        public AuthController(ApplicationDbContext db, PasswordHasher<Usuarios> hasher, EmailService emailService, TOTPService totpService)
        {
            _db = db;
            _hasher = hasher;

            _totpService = totpService;
            _emailService = emailService;
        }

        #region Session Management

        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult Registro()
        {
            return View();
        }

        [HttpPost]
        [SoloParaAnonimos]
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
        [SoloParaAnonimos]
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

                TempData["Exito"] = "✅ Usuario registrado correctamente. Ahora podés iniciar sesión.";
                return RedirectToAction("Login");
            }

            TempData["Error"] = "❌ Código incorrecto o expirado. Intenta nuevamente.";
            return View(); // vuelve a VerificarOTP.cshtml mostrando el error
        }

        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [SoloParaAnonimos]
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
                if (user.Autenticacion2FAActiva && !string.IsNullOrEmpty(user.ClaveTOTP))
                {
                    // Guardamos quién está intentando loguearse
                    HttpContext.Session.SetString("LOGIN_2FA_EMAIL", user.Email);
                    return RedirectToAction("VerificarTOTP");
                }

                // Sin 2FA → login normal
                HttpContext.Session.SetString("UsuarioEmail", user.Email);
                return RedirectToAction("Index", "Home");
            }

            ViewBag.Error = "Contraseña incorrecta.";
            return View();
        }

        [HttpGet]
        [SoloParaAnonimos]
        public IActionResult VerificarTOTP()
        {
            var pendingEmail = HttpContext.Session.GetString("LOGIN_2FA_EMAIL");
            if (string.IsNullOrEmpty(pendingEmail))
                return RedirectToAction("Login");

            return View();
        }

        [HttpPost]
        [SoloParaAnonimos]
        public IActionResult VerificarTOTP(string codigo)
        {
            var email = HttpContext.Session.GetString("LOGIN_2FA_EMAIL");
            if (string.IsNullOrEmpty(email))
                return RedirectToAction("Login");

            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);
            if (user == null || string.IsNullOrEmpty(user.ClaveTOTP))
            {
                TempData["Error"] = "No hay 2FA configurada para este usuario.";
                return RedirectToAction("Login");
            }

            var code = new string((codigo ?? "").Where(char.IsDigit).ToArray());
            if (code.Length != 6 || !_totpService.VerificarCodigo(user.ClaveTOTP, code))
            {
                TempData["Error"] = "Código TOTP inválido. Intenta nuevamente.";
                return RedirectToAction("VerificarTOTP");
            }

            // OK → completar login
            HttpContext.Session.Remove("LOGIN_2FA_EMAIL");
            HttpContext.Session.SetString("UsuarioEmail", user.Email);
            return RedirectToAction("Index", "Home");
        }
        
        [HttpGet]
        [Autenticado]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Auth");
        }

        #endregion


        #region TOTP

        [HttpGet]
        [Autenticado]
        public IActionResult ConfigurarAuthenticator()
        {
            var email = HttpContext.Session.GetString("UsuarioEmail");
            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);

            ViewBag.Activado = user?.Autenticacion2FAActiva ?? false;
            return View();
        }

        [HttpGet]
        [Autenticado]
        public IActionResult QrPng()
        {
            var email = HttpContext.Session.GetString("UsuarioEmail");
            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);
            if (user?.Autenticacion2FAActiva == true)
                return NotFound(); // ya no generamos QR si está activo

            var secret = GetOrCreateSetupSecret(); // el helper que agregamos antes
            var uri = _totpService.GenerarQrCodeUri(email ?? "preview@local", secret);
            var png = _totpService.GenerarQrCodeImage(uri);

            Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0";
            return File(png, "image/png");
        }

        private const string SESSION_TOTP_SETUP = "TOTP_SECRET_SETUP";
        private string GetOrCreateSetupSecret()
        {
            var secret = HttpContext.Session.GetString(SESSION_TOTP_SETUP);
            if (string.IsNullOrEmpty(secret))
            {
                secret = _totpService.GenerarClave();
                HttpContext.Session.SetString(SESSION_TOTP_SETUP, secret);
            }
            return secret;
        }

        [HttpPost]
        [Autenticado]
        public IActionResult ActivarAuthenticator(string codigo)
        {
            var code = new string((codigo ?? "").Where(char.IsDigit).ToArray());
            if (code.Length != 6) { TempData["Error"] = "Ingresa un código de 6 dígitos."; return RedirectToAction("ConfigurarAuthenticator"); }

            var secret = HttpContext.Session.GetString(SESSION_TOTP_SETUP);
            if (string.IsNullOrEmpty(secret)) { TempData["Error"] = "No se encontró el secreto de configuración. Recarga la página."; return RedirectToAction("ConfigurarAuthenticator"); }

            if (!_totpService.VerificarCodigo(secret, code)) { TempData["Error"] = "Código incorrecto. Intenta nuevamente."; return RedirectToAction("ConfigurarAuthenticator"); }

            var email = HttpContext.Session.GetString("UsuarioEmail");
            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);
            if (user == null) { TempData["Error"] = "Usuario no encontrado."; return RedirectToAction("ConfigurarAuthenticator"); }

            user.ClaveTOTP = secret;
            user.Autenticacion2FAActiva = true;
            _db.SaveChanges();

            HttpContext.Session.Remove(SESSION_TOTP_SETUP);

            TempData["Exito"] = "✅ Autenticación de 2 factores activada.";
            return RedirectToAction("ConfigurarAuthenticator");
        }

        [HttpPost]
        [Autenticado]
        public IActionResult DesactivarAuthenticator(string codigo)
        {
            var code = new string((codigo ?? "").Where(char.IsDigit).ToArray());
            if (code.Length != 6) { TempData["Error"] = "Ingresa un código de 6 dígitos."; return RedirectToAction("ConfigurarAuthenticator"); }

            var email = HttpContext.Session.GetString("UsuarioEmail");
            var user = _db.Usuarios.FirstOrDefault(u => u.Email == email);
            if (user == null || !user.Autenticacion2FAActiva || string.IsNullOrEmpty(user.ClaveTOTP))
            {
                TempData["Error"] = "No hay 2FA activa para este usuario.";
                return RedirectToAction("ConfigurarAuthenticator");
            }

            if (!_totpService.VerificarCodigo(user.ClaveTOTP, code))
            {
                TempData["Error"] = "❌ Código incorrecto. No se pudo desactivar.";
                return RedirectToAction("ConfigurarAuthenticator");
            }

            user.ClaveTOTP = null;
            user.Autenticacion2FAActiva = false;
            _db.SaveChanges();

            TempData["Exito"] = "🔓 2FA desactivada correctamente.";
            return RedirectToAction("ConfigurarAuthenticator");
        }

        #endregion
    }
}