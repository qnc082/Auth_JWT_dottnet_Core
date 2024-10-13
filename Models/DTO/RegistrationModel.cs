using System.ComponentModel.DataAnnotations;

namespace Auth.Models.DTO
{
    public class RegistrationModel
    {
        [Required]
        public string Name { get; set; }
        [Required]
        public string UserName { get; set; }
        [Required]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
    }
}
