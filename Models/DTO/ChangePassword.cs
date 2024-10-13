using System.ComponentModel.DataAnnotations;

namespace Auth.Models.DTO
{
    public class ChangePassword
    {
        [Required]
        public string UserName { get; set; }
        [Required]
        public string CurrentPassword { get; set; }
        [Required]
        public string NewPassword { get; set; }
        [Required]
        [Compare(nameof(NewPassword))]
        public string ConfirmPassword { get; set; }
    }
}
