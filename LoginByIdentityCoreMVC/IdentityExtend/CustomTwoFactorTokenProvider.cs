using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using System.Threading.Tasks;

namespace LoginByIdentityCoreMVC.IdentityExtend
{
    public class CustomTwoFactorTokenProvider<TUser> : IUserTwoFactorTokenProvider<TUser>
        where TUser : class
    {
        public async Task<string> GenerateAsync(string purpose, UserManager<TUser> userManager, TUser user)
        {
            if (purpose == "TwoFactor")
            {
                var code = GenerateRandomCode(); // Your code generation logic
                await StoreUserGeneratedCode(userManager,user, code);
                return code;
            }

            throw new NotSupportedException("Unsupported token purpose.");
        }

        public async Task<bool> ValidateAsync(string purpose, string token, UserManager<TUser> userManager, TUser user)
        {
            if (purpose == "TwoFactor")
            {
                var storedCode = await GetUserStoredCode(userManager, user); // Your logic to retrieve the stored code
                return await Task.FromResult(token == storedCode);
            }

            throw new NotSupportedException("Unsupported token purpose.");
        }

        public Task<bool> CanGenerateTwoFactorTokenAsync(UserManager<TUser> userManager, TUser user)
        {
            return Task.FromResult(true); // Your logic to determine if the user can generate a token
        }

        private string GenerateRandomCode()
        {
            // Implement your logic to generate a random code
            Random random = new Random();
            return random.Next(100000, 999999).ToString();
        }

        private async Task<string> GetUserStoredCode(UserManager<TUser> userManager, TUser user)
        {
            // Retrieve the stored code from the user's claims
            var claim = await userManager.GetClaimsAsync(user);
            return claim.FirstOrDefault(c => c.Type == "TwoFactorCode")?.Value ?? string.Empty;
        }

        private async Task StoreUserGeneratedCode(UserManager<TUser> userManager, TUser user, string code)
        {
            // Store the generated code as a claim for the user
            await userManager.RemoveClaimsAsync(user, await userManager.GetClaimsAsync(user));
            await userManager.AddClaimAsync(user, new Claim("TwoFactorCode", code));
        }
    }


}
