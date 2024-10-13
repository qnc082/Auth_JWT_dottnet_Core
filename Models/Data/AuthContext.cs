using Auth.Models.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Reflection.Emit;

namespace Auth.Models.Data
{
    public class AuthContext : IdentityDbContext<ApplicationUser>
    {
        public AuthContext(DbContextOptions<AuthContext> options) : base(options)
        {
        }

        public DbSet<TokenInfo> TokenInfo { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            builder.HasDefaultSchema("Auth");
            base.OnModelCreating(builder);
        }
    }
}
