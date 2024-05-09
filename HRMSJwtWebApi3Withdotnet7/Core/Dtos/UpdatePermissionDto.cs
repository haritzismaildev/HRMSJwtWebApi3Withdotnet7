using System.ComponentModel.DataAnnotations;

namespace HRMSJwtWebApi3Withdotnet7.Core.Dtos
{
    public class UpdatePermissionDto
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; }
    }
}
