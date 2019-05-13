using System.Security.Claims;
using System.Threading.Tasks;

namespace AzureFunctions.Security.Auth0
{
    public interface IAuthenticationService
    {
        Task<ClaimsPrincipal> ValidateTokenAsync(string token);
    }
}