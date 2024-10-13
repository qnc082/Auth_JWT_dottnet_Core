using Auth.Models.DTO;
using System.Security.Claims;

namespace Auth.Repositories
{
    public interface ITokenService
    {
        public TokenResponse GetToken(IEnumerable<Claim> claims);
        public string GetRefreshToken();
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
    }
}
