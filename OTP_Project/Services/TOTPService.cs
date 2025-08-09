using OtpNet;
using QRCoder;

namespace OTP_Project.Services
{
    public class TOTPService
    {
        public string GenerarClave()
        {
            var clave = KeyGeneration.GenerateRandomKey(20);
            return Base32Encoding.ToString(clave);
        }

        public string GenerarQrCodeUri(string email, string claveSecreta)
        {
            return $"otpauth://totp/OTP_Project:{email}?secret={claveSecreta}&issuer=OTP_Project";
        }

        public byte[] GenerarQrCodeImage(string qrUri)
        {
            using var qrGenerator = new QRCodeGenerator();
            var qrData = qrGenerator.CreateQrCode(qrUri, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new BitmapByteQRCode(qrData);
            return qrCode.GetGraphic(8);
        }

        public bool VerificarCodigo(string claveSecreta, string codigo)
        {
            var totp = new Totp(Base32Encoding.ToBytes(claveSecreta));
            return totp.VerifyTotp(codigo, out long _);
        }
    }
}