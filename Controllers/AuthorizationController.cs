using Auth.Models;
using Auth.Models.Data;
using Auth.Models.DTO;
using Auth.Models.Entities;
using Auth.Repositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Auth.Controllers
{
    [Route("api/[controller]/[action]")]
    [ApiController]
    public class AuthorizationController : ControllerBase
    {
        private readonly AuthContext _authContext;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ITokenService _tokenService;

        public AuthorizationController(
            AuthContext authContext,
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ITokenService tokenService)
        {
            _authContext = authContext;
            _userManager = userManager;
            _roleManager = roleManager;
            _tokenService = tokenService;
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var user = await _userManager.FindByNameAsync(loginModel.UserName);

            if (user is null) { return BadRequest(); }

            var isChecked = await _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (isChecked)
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name,user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString())
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = _tokenService.GetToken(authClaims);

                var refreshToken = _tokenService.GetRefreshToken();

                var tokenInfo = await _authContext.TokenInfo.FirstOrDefaultAsync(x => x.UserName.Equals(user.Name));

                if (tokenInfo is null)
                {
                    var info = new TokenInfo
                    {
                        UserName = user.UserName,
                        RefreshToken = refreshToken,
                        RefreshTokenExpiry = DateTimeOffset.UtcNow.AddDays(1),
                    };
                    _authContext.TokenInfo.Add(info);
                }
                else
                {
                    tokenInfo.RefreshToken = refreshToken;
                    tokenInfo.RefreshTokenExpiry = DateTimeOffset.UtcNow.AddDays(1);
                }

                try
                {
                    await _authContext.SaveChangesAsync();

                }
                catch (Exception e)
                {

                    return BadRequest(e.Message);
                }
                return Ok(new LoginResponse
                {
                    Name = user.Name,
                    UserName = user.UserName,
                    Token = token.TokenString,
                    RefreshToken = refreshToken,
                    Expiration = token.ValidTo.ToLocalTime().ToString("R"),
                    StatusCode = 1,
                    Message = "Logged in"
                });
            }

            return Ok(new LoginResponse
            {

                Token = string.Empty,
                Expiration = null,
                StatusCode = 0,
                Message = "Invalid username or password"
            });
        }

        [HttpPost]
        public async Task<IActionResult> Registration([FromBody] RegistrationModel registrationModel)
        {
            var status = new Status();
            if (!ModelState.IsValid)
            {
                status.StatusCode = 0;
                status.Message = "Kindly provide required fields";
                return Ok(status);
            }
            var userExists = await _userManager.FindByEmailAsync(registrationModel.UserName);

            if (userExists is not null)
            {
                status.StatusCode = 0;
                status.Message = "Kindly provide valid credentials info!";
                return Ok(status);
            }

            var user = new ApplicationUser
            {
                Name = registrationModel.Name,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = registrationModel.Email,
                UserName = registrationModel.UserName,
            };

            //
            var result = await _userManager.CreateAsync(user, registrationModel.Password);

            if (!result.Succeeded)
            {
                status.StatusCode = 0;
                status.Message = "User not created!";
                return Ok(status);
            }

            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            if (await _roleManager.RoleExistsAsync(UserRoles.User))
                await _userManager.AddToRoleAsync(user, UserRoles.User);

            status.StatusCode = 1;
            status.Message = "Successfully registered!";
            return Ok(status);

        }

        [HttpPost]
        public async Task<IActionResult> AdminRegistration([FromBody] RegistrationModel registrationModel)
        {
            var status = new Status();
            if (!ModelState.IsValid)
            {
                status.StatusCode = 0;
                status.Message = "Kindly provide required fields";
                return Ok(status);
            }
            var userExists = await _userManager.FindByEmailAsync(registrationModel.UserName);

            if (userExists is not null)
            {
                status.StatusCode = 0;
                status.Message = "Kindly provide required fields";
                return Ok(status);
            }

            var user = new ApplicationUser
            {
                Name = registrationModel.Name,
                SecurityStamp = Guid.NewGuid().ToString(),
                Email = registrationModel.Email,
                UserName = registrationModel.UserName,
            };

            //
            var result = await _userManager.CreateAsync(user, registrationModel.Password);

            if (!result.Succeeded)
            {
                status.StatusCode = 0;
                status.Message = "User not created!";
                return Ok(status);
            }

            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);

            status.StatusCode = 1;
            status.Message = "Successfully registered!";
            return Ok(status);

        }

        [HttpPost]
        public async Task<IActionResult> ChangePassword(ChangePassword model)
        {
            var status = new Status();

            if (!ModelState.IsValid)
            {
                status.StatusCode = 0;
                status.Message = "Kindly Pass all fields";
                return Ok(status);
            }
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user is null)
            {
                status.StatusCode = 0;
                status.Message = "Invalid UserName!";
                return Ok(status);
            }

            if (await _userManager.CheckPasswordAsync(user, model.CurrentPassword))
            {
                status.StatusCode = 0;
                status.Message = "Invalid current password!";
                return Ok(status);
            }

            var result = await _userManager.ChangePasswordAsync(user, model.CurrentPassword, model.NewPassword);
            if (!result.Succeeded)
            {
                status.StatusCode = 0;
                status.Message = "Failed to change password";
                return Ok(status);
            }
            status.StatusCode = 1;
            status.Message = "Password changed!";
            return Ok(result);
        }
    }
}
