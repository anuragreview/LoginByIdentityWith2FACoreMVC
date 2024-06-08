namespace LoginByIdentityCoreMVC.ViewModels
{
    public class Verify2faViewModel
    {
        public string? Provider { get; set; }
        public string? Code { get; set; }
        public bool RememberMe { get; set; }
        public bool IsDeviceRemembered { get; set; }
    }
}
