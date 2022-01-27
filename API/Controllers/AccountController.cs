using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        public DataContext _context { get; }
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            this._context = context;
            
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDTO registerDTO)
        {
            if(await UserExists(registerDTO.UserName)) return BadRequest("Username is already taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser()
            {
            UserName = registerDTO.UserName.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDTO.Password)),
            PasswordSalt = hmac.Key
            };
        _context.Users.Add(user);
        await _context.SaveChangesAsync();

        return new UserDto {
            UserName = user.UserName,
            Token = _tokenService.CreateToken(user)
        };
        }       
        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
         var user =  await _context.Users.SingleOrDefaultAsync(user=> user.UserName == loginDto.Username);

         if(user == null)
         {
             return Unauthorized("Invalid username");

         }

         using var hmac  = new HMACSHA512(user.PasswordSalt);

         var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

         for(int i = 0; i< computedHash.Length; i++)
         {
             if(computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");   
         }

         return new UserDto {
            UserName = user.UserName,
            Token = _tokenService.CreateToken(user)
        };
        }

        private async Task<bool> UserExists(string username)
        {
            return await _context.Users.AnyAsync(user => user.UserName == username.ToLower());

        }
    }
}