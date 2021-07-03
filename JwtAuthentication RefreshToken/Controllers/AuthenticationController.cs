using JwtAuthentication.Models.Context;
using JwtAuthentication.Models.ViewModels;
using JwtAuthentication.Models.ViewModels.Atuh;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Utilites;

namespace JwtAuthentication.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly JwtConfig _jwtConfig;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly JwtContext _apiDbContext;

        private readonly string SendedConfirmKey = "SendedConfirmKey";

        public AuthenticationController(UserManager<IdentityUser> userManager, IOptionsMonitor<JwtConfig> optionsMonitor, SignInManager<IdentityUser> signInManager, TokenValidationParameters tokenValidationParameters, JwtContext apiDbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _signInManager = signInManager;
            _tokenValidationParameters = tokenValidationParameters;
            _apiDbContext = apiDbContext;
        }


        /// <summary>
        /// Action For Get Access Token
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("/Login")]
        public async Task<ActionResult<AuthResult>> LoginAsync([FromBody] UserLoginRequest user)
        {
            if (ModelState.IsValid)
            {
                // check if the user with the same email exist
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>(){
                                        "User Is Invalid"
                                    }
                    });
                }

                // Now we need to check if the user has inputed the right password
                var signIn = await _signInManager.PasswordSignInAsync(existingUser, user.Password, false, true);

                //check use allow to sign in
                if (signIn.IsNotAllowed is true)
                {
                    //if send one or more confirm email, dose not send again
                    var confirmSended = HttpContext.Session.GetInt32(SendedConfirmKey);
                    if (confirmSended.HasValue is false)
                    {
                        await SendConfirmationEmail(existingUser);
                    }
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Email is not valid" }
                    });
                }
                if (signIn.IsLockedOut is true)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Your Account was lockedout for few time" }
                    });
                }
                if (signIn.Succeeded)
                {
                    var jwtToken =await  GenerateJwtTokenAsync(existingUser);

                    return Ok(jwtToken);
                }
                else
                {
                    // We dont want to give to much information on why the request has failed for security reasons
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>(){
                                         "Invalid Login"
                                    }
                    });
                }
            }

            return BadRequest(new AuthResult()
            {
                Result = false,
                Messages = new List<string>(){
                      "Inputs not valid"
                    }
            });
        }


        /// <summary>
        /// Action For Store User Data And Get Confirmation Email
        /// </summary>
        /// <param name="user"></param>
        /// <returns></returns>
        [HttpPost("/Register")]
        public async Task<ActionResult<AuthResult>> RegisterAsync([FromBody] UserRegistrationRequestDto user)
        {
            // Check if the incoming request is valid
            if (ModelState.IsValid)
            {
                // check i the user with the same email exist
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if (existingUser != null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "User was exsist" }
                    });
                }

                var newUser = new IdentityUser() { Email = user.Email, UserName = user.Name };
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                if (isCreated.Succeeded)
                {
                    //var jwtToken = GenerateJwtToken(newUser);
                    await SendConfirmationEmail(newUser);
                    return Ok(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "For activation your email click sended link in your email" }
                    });
                }

                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Messages = isCreated.Errors.Select(x => x.Description).ToList()
                });

            }

            return BadRequest(new AuthResult()
            {
                Result = false,
                Messages = new List<string>() { "Inputs not valid" }
            });
        }
        /// <summary>
        /// For Recovery Password:
        /// First: Send User Email From This Action
        /// Second: You Get An Email, Open It, Click The Link,
        /// Impelemnt A View For That Link. Get Email Addresss And Token
        /// Thered: Send Token,Email,NewPassword To RecoveryPasswordConfirm Action 
        /// </summary>
        /// <param name="email"></param>
        /// <returns></returns>
        [HttpGet("RecoveryPassword")]
        public async Task<ActionResult<AuthResult>> RecoveryPasswordAsync(string email)
        {
            if (ModelState.IsValid)
            {
                var exsistUser = await _userManager.FindByEmailAsync(email);
                if (exsistUser is null)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "User not exsist" } });

                }
                string tokenGenreated = await _userManager.GeneratePasswordResetTokenAsync(exsistUser);

                string link = Url.Action("RecoveryPassword", "Authentication", new { token = tokenGenreated, email = email,newpassword="78452211212" });
                string body = $"Hello frend " +
                        $"</br>" +
                        $" For validating Email click below link" +
                        $" </br> </br>" +
                        $" <a href={$"{link}"}+> Recovery password </a>";

                SendEmail.send("Recovey Password", body, email, exsistUser.UserName);


                return Ok(new AuthResult()
                {
                    Messages = new List<string> { "Sended email for validate email" }
                }); ;
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
        }
        /// <summary>
        /// This Action For Recovery Password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("RecoveryPassword")]
        public async Task<ActionResult<AuthResult>> RecoveryPasswordConfirmAsync([FromBody] RecoveryPasswordConfirmViewModel model)
        {
            if (ModelState.IsValid)
            {
                model.Token = System.Net.WebUtility.UrlDecode(model.Token);

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user is null)
                {
                    return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
                }
                var changePassword = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);

                if (changePassword.Succeeded)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "Password Success changed" } });
                }
                else
                {
                    return BadRequest(new AuthResult() { Messages = changePassword.Errors.Select(x => x.Description).ToList() });
                }
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });
        }
        /// <summary>
        /// This Action For Active Confirmation. User After Confirm Email Can Get Token.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        /// <summary>
        /// This Action For Active Confirmation. User After Confirm Email Can Get Token.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpGet("ConfirmEmail")]
        public async Task<ActionResult<AuthResult>> ConfirmEmailAsync([FromQuery] EmailConfirmViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.email);
                if (user == null)
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Messages = new List<string>() { "Link not valid" }
                    });
                var result = await _userManager.ConfirmEmailAsync(user, model.token);
                return Ok(new AuthResult()
                {
                    Result = false,
                    Messages = new List<string>() { "Please login" }
                }); ;
            }
            return BadRequest(new AuthResult() { Messages = new List<string>() { "Inputs not valid" } });

        }
        /// <summary>
        /// for change the password
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        [HttpPost("ResetPassword")]
        public async Task<ActionResult<AuthResult>> ResetPasswordAsync([FromBody] RestPasswordViewModel model)
        {
            if (ModelState.IsValid)
            {
                if (User.Identity.IsAuthenticated is false)
                {
                    return BadRequest(new AuthResult()
                    {
                        Messages = new List<string>() { "You're not login" }
                    });
                }
                var username = User.Claims.FirstOrDefault(a => a.Type == ClaimTypes.Email).Value;
                var user = await _userManager.FindByEmailAsync(username);

                var changePassword = await _userManager.ChangePasswordAsync(user, model.OldPassword, model.NewPassword);
                if (changePassword.Succeeded)
                {
                    return Ok(new AuthResult() { Messages = new List<string>() { "Your passwod successfuly chenged" } });
                }
                else
                {
                    return BadRequest(new AuthResult() { Messages = changePassword.Errors.Select(a => a.Description).ToList() });
                }
                //_userManager.GetUserAsync()
            }
            return BadRequest(new AuthResult()
            {
                Messages = new List<string>() { "Inputs not valid" }
            });
        }

        private async Task SendConfirmationEmail(IdentityUser user)
        {
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action("ConfirmEmail", "Authentication", new { token, email = user.Email }, Request.Scheme);
            var body = $"hello frend " +
                $"</br>" +
                $" For validate your email click below link" +
                $" </br> </br>" +
                $" <a href={$"{confirmationLink}"}> validate email </a>";
            SendEmail.send("validate email", body, user.Email, user.UserName);
            HttpContext.Session.SetInt32(SendedConfirmKey, 1);

        }
        private async Task<AuthResult> GenerateJwtTokenAsync(IdentityUser user)
        {
            // Now its ime to define the jwt token which will be responsible of creating our tokens
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            // We get our secret from the appsettings
            //for encript token genrated
            var Secretkey = Encoding.ASCII.GetBytes(_jwtConfig.Secret);
            var SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Secretkey), SecurityAlgorithms.HmacSha256Signature);

            //for encript values in token
            var EncryptionKey = Encoding.ASCII.GetBytes(_jwtConfig.EncryptionKey);
            var EncryptingCredentials = new EncryptingCredentials(new SymmetricSecurityKey(EncryptionKey), SecurityAlgorithms.Aes128KW,SecurityAlgorithms.Aes128CbcHmacSha256);

            // we define our token descriptor
            // We need to utilise claims which are properties in our token which gives information about the token
            // which belong to the specific user who it belongs to
            // so it could contain their id, name, email the good part is that these information
            // are generated by our server and identity framework which is valid and trusted
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserName),
                // the JTI is used for our refresh token 
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
                // the life span of the token needs to be shorter and utilise refresh token to keep the user signedin
                // but since this is a demo app we can extend it to fit our current need

                //jwt expiration
                Expires = DateTime.UtcNow.AddSeconds(_jwtConfig.ExpiryTimeFrame),
                // here we are adding the encryption alogorithim information which will be used to decrypt our token
                SigningCredentials = SigningCredentials,

                EncryptingCredentials = EncryptingCredentials
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                IsUsed = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddYears(1),
                IsRevoked = false,
                Token = RandomString(25) + Guid.NewGuid(),
                User=user
            };

            await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
            await _apiDbContext.SaveChangesAsync();

            return new AuthResult()
            {
                Token = jwtToken,
                Result = true,
                RefreshToken = refreshToken.Token
            };
        }
        private string RandomString(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            return new string(Enumerable.Repeat(chars, length)
            .Select(s => s[random.Next(s.Length)]).ToArray());
        }


        /// <summary>
        /// this is action for refreshing token
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var res = await VerifyToken(tokenRequest);

                if (res == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Messages = new List<string>() {
                    "Invalid tokens"
                },
                        Result = false
                    });
                }

                return Ok(res);
            }

            return BadRequest(new AuthResult()
            {
                Messages = new List<string>() {
                "Invalid payload"
            },
                Result = false
            });
        }

        private async Task<AuthResult> VerifyToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {
                // This validation function will make sure that the token meets the validation parameters
                // and its an actual jwt token not just a random string
                var principal = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParameters, out var validatedToken);

                // Now we need to check if the token has a valid security algorithm
                if (validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.Aes128KW, StringComparison.InvariantCultureIgnoreCase);

                    if (result == false)
                    {
                        return null;
                    }
                }

                // Will get the time stamp in unix time
                var utcExpiryDate = long.Parse(principal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                // we convert the expiry date from seconds to the date
                var expDate = UnixTimeStampToDateTime(utcExpiryDate);

                if (expDate > DateTime.UtcNow)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "We cannot refresh this since the token has not expired" },
                        Result = false
                    };
                }

                // Check the token we got if its saved in the db
                var storedRefreshToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if (storedRefreshToken == null)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "refresh token doesnt exist" },
                        Result = false
                    };
                }

                // Check the date of the saved token if it has expired
                if (DateTime.UtcNow > storedRefreshToken.ExpiryDate)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "token has expired, user needs to relogin" },
                        Result = false
                    };
                }

                // check if the refresh token has been used
                if (storedRefreshToken.IsUsed)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "token has been used" },
                        Result = false
                    };
                }

                // Check if the token is revoked
                if (storedRefreshToken.IsRevoked)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "token has been revoked" },
                        Result = false
                    };
                }

                // we are getting here the jwt token id
                var jti = principal.Claims.SingleOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                // check the id that the recieved token has against the id saved in the db
                if (storedRefreshToken.JwtId != jti)
                {
                    return new AuthResult()
                    {
                        Messages = new List<string>() { "the token doenst mateched the saved token" },
                        Result = false
                    };
                }

                storedRefreshToken.IsUsed = true;
                _apiDbContext.RefreshTokens.Update(storedRefreshToken);
                await _apiDbContext.SaveChangesAsync();

                var dbUser = await _userManager.FindByIdAsync(storedRefreshToken.UserId);
                return await GenerateJwtTokenAsync(dbUser);
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            // Unix timestamp is seconds past epoch
            System.DateTime dtDateTime = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
            dtDateTime = dtDateTime.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dtDateTime;
        }
    }
}
