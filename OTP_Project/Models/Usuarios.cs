using System.ComponentModel.DataAnnotations;

namespace OTP_Project.Models
{
    public class Usuarios
    {
        [Key]
        public Int64 Id { get; set; }
        [Required]
        public String Email { get; set; }
        [Required]
        public String PasswordHash { get; set; }
        public String? ClaveTOTP { get; set; }
        public Boolean Autenticacion2FAActiva { get; set; } = false;
    }
}