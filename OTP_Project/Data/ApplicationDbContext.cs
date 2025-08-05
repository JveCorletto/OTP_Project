using OTP_Project.Models;
using Microsoft.EntityFrameworkCore;

namespace OTP_Project.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : base(options)
        {
        }

        public DbSet<Usuarios> Usuarios { get; set; }
    }
}