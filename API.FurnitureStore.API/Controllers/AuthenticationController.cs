﻿using API.FurnitureStore.API.Configuration;
using API.FurnitureStore.Shared.Auth;
using API.FurnitureStore.Shared.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore.Metadata.Internal;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace API.FurnitureStore.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtConfig _jwtConfig;
        private readonly IEmailSender _emailSender;

        public AuthenticationController(UserManager<IdentityUser> userManager,
                                        IOptions<JwtConfig> jwtConfig,
                                        IEmailSender emailSender)
        {
            _userManager = userManager;
            _jwtConfig = jwtConfig.Value;
            _emailSender = emailSender;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody]UserRegistrationRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }
            var emailExist = await _userManager.FindByEmailAsync(request.EmailAddress);

            if (emailExist != null)
            {
                return BadRequest(new AuthResult()
                {
                    Result = false,
                    Errors = new List<string>()
                    {
                        "Email already exist."
                    }
                });
            }
                //create user
                var user = new IdentityUser()
                {
                    Email = request.EmailAddress,
                    UserName = request.EmailAddress,
                    EmailConfirmed = false
                };

                var isCreated = await _userManager.CreateAsync(user,request.Password);
                if (isCreated.Succeeded)
                {
                    //var token = GenerateToken(user);
                    await SendVerificationEmail(user);
                    return Ok(new AuthResult()
                    {
                        Result = true
                    });
                }
                else
                {
                    var errors = new List<string>();
                    foreach (var err in isCreated.Errors)
                    {
                        errors.Add(err.Description);
                    }
                    return BadRequest(new AuthResult
                    {
                        Result = false,
                        Errors = errors
                    });
                }
                
            return BadRequest(new AuthResult
            {
                Result = false,
                Errors = new List<string>() { "User couldn't be created." }
            });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto request)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser == null)
            {
                return BadRequest(new AuthResult
                {
                    Result = false,
                    Errors = new List<string>() { "Invalid payload" }
                });
            }
            if (!existingUser.EmailConfirmed)
            {
                return BadRequest(new AuthResult
                {
                    Result = false,
                    Errors = new List<string>() { "Email needs to be confirmed." }
                });
            }
            var checkUserPass = await _userManager.CheckPasswordAsync(existingUser, request.Password);
            if (!checkUserPass)
            {
                return BadRequest(new AuthResult
                {
                    Result = false,
                    Errors = new List<string>() { "Invalid Credentials" }
                });
            }
            var token = GenerateToken(existingUser);
            return Ok(new AuthResult
            {
                Token = token, 
                Result = true
            });
        }

        [HttpGet("ConfirmationEmail")]
        public async Task<IActionResult> ConfirmationEmail(string userId, string code)
        {
            if(string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return BadRequest(new AuthResult
                {
                    Errors = new List<string> { "Invalid email confirmation url" },
                    Result = false
                });
            }
            var user =await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound($"Unable to load user with id '{userId}'.");
            }
            code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            var result = await _userManager.ConfirmEmailAsync(user,code);

            var status = result.Succeeded ? "Thank you for confirmation your email."
                                            : "There has been an error confirming your email.";
            return Ok(status);
        }

        private string GenerateToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtConfig.Secret);
            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new ClaimsIdentity(new[]
                {
                    new Claim("Id",user.Id),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToString())
                })),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);

            return jwtTokenHandler.WriteToken(token);
        }

        private async Task SendVerificationEmail(IdentityUser user)
        {
            var verificationCode = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            verificationCode = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(verificationCode));

            //example: https://localhost:8080/api/authentication/verifymail/userId=exampleuserId&code=examplecode
            var callbackUr1 = $@"{Request.Scheme}://{Request.Host}{Url.Action("ConfirmationEmail", controller: "Authentication",
                                    new { userId = user.Id, code = verificationCode })}";
            var emailBody = $"Please confirm your account by <a href='{HtmlEncoder.Default.Encode(callbackUr1)}'>clicking here</a>";

            await _emailSender.SendEmailAsync(user.Email, "Confirm your email",emailBody);


        }
    
    }
}
