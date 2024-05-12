using Microsoft.AspNetCore.Identity;

namespace HRMSJwtWebApi3Withdotnet7.Core.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
