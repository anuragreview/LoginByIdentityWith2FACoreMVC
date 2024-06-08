using Microsoft.AspNetCore.Identity;

namespace LoginByIdentityCoreMVC.Models
{
    public class ApplicationUser : IdentityUser
    {
        public string? DeviceIdentifier { get; set; }
    }
}
