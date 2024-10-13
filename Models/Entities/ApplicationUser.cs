using Microsoft.AspNetCore.Identity;

namespace Auth.Models.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string? Name { get; set; }
    }
}
