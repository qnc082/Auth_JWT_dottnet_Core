using Auth.Models.Data;
using Auth.Models.DTO;
using Auth.Repositories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace Auth.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly AuthContext _authContext;
        private readonly ITokenService _tokenService;

        public TokenController(AuthContext authContext, ITokenService tokenService)
        {
            _authContext = authContext;
            _tokenService = tokenService;
        }

        [HttpPost]
        public async Task<IActionResult> RefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            if (refreshTokenRequest is null) { BadRequest("Invalid request!"); }

            var accessToken = refreshTokenRequest?.AccessToken;
            var refreshToken = refreshTokenRequest?.RefreshToken;

            if (accessToken is null) return BadRequest("Invalid access token!");
            if (refreshToken is null) return BadRequest("Invalid access token!");

            var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);



            var userName = principal?.Identity?.Name;
            var user = await _authContext.TokenInfo.SingleOrDefaultAsync(x => x.UserName.Equals(userName));



            if (principal is null) return BadRequest("");
            var newAccessToken = _tokenService.GetToken(principal.Claims);
            var newRefreshToken = _tokenService.GetRefreshToken();


            if (user?.RefreshToken != refreshToken || user?.RefreshTokenExpiry <= DateTimeOffset.Now) return BadRequest("Invalid request!");

            if (user is null) return BadRequest();
            user.RefreshToken = newRefreshToken;
            await _authContext.SaveChangesAsync();

            return Ok(new RefreshTokenRequest()
            {
                AccessToken = newAccessToken.TokenString ?? string.Empty,
                RefreshToken = newRefreshToken
            });
        }

        [HttpPost]
        public async Task<IActionResult> Revoke()
        {
            var userName = User?.Identity?.Name;

            var user = await _authContext.TokenInfo.SingleOrDefaultAsync(x => x.UserName.Equals(userName));

            if (user is null) return BadRequest();

            user.RefreshToken = null;
            _authContext.SaveChanges();
            return Ok(true);

        }
    }
}
