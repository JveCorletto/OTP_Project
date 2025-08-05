using System.Net;
using System.Net.Mail;

namespace OTP_Project.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task EnviarOTP(string destinoEmail, string codigo)
        {
            var remitente = _config["Email:From"];
            var password = _config["Email:Password"];
            var smtp = _config["Email:Smtp"];
            var puerto = int.Parse(_config["Email:Port"]);

            var mensaje = new MailMessage(remitente, destinoEmail)
            {
                Subject = "Tu código OTP",
                Body = $"Tu código de verificación es: {codigo}",
                IsBodyHtml = false
            };

            using var cliente = new SmtpClient(smtp, puerto)
            {
                Credentials = new NetworkCredential(remitente, password),
                EnableSsl = true
            };

            await cliente.SendMailAsync(mensaje);
        }
    }
}