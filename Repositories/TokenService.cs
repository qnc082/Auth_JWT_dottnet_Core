using Auth.Models.DTO;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Auth.Repositories
{
    public class TokenService : ITokenService
    {
        private readonly IConfiguration _configuration;

        public TokenService(IConfiguration configuration)
        {
            _configuration = configuration;
        }
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false,
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;

            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);

            var jwtToken = securityToken as JwtSecurityToken;
            if(jwtToken is null || !jwtToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256)) 
            { throw new SecurityTokenException("Token Invalid!"); }
            return principal;
        }

        public string GetRefreshToken()
        {
            var random = new byte[32];
            using (var rng = RandomNumberGenerator.Create()) 
            { rng.GetBytes(random); return Convert.ToBase64String(random); }
        }

        public TokenResponse GetToken(IEnumerable<Claim> claims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(1),
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );
            string tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return new TokenResponse() 
            { 
                TokenString = tokenString,
                //ValidTo = token.ValidTo ,
                ValidTo = DateTime.SpecifyKind(token.ValidTo, DateTimeKind.Local),
        };

        }
    }
}
