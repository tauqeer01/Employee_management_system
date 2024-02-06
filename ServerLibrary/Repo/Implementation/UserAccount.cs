
using BaseLibrary.DTOs;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repo.Contracts;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;


namespace ServerLibrary.Repo.Implementation
{
	public class UserAccount(IOptions<JwtSection> config , AppDbContext dbContext) : IUserAccount
	{
		public async Task<GeneralResponse> CreateAsync(Register user)
		{
			if(user is null) return new GeneralResponse(false, "Model is empty");
			var checkUser = await FindUserByEmail (user.Email);
			if (checkUser != null) return new GeneralResponse(false, "User Register Already");

			//save user
			var applicationUser = await AddToDatabase(new ApplicationUser()
			{
				Name=user.FullName,
				Email=user.Email,
				Password= BCrypt.Net.BCrypt.HashPassword(user.Password)
			});

			//check , create and assign roles
			var checkAdminRole = await dbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));
			if(checkAdminRole is null)
			{
				var createAdminRole = await AddToDatabase(new SystemRole()
				{
					Name= Constants.Admin
				});
				await AddToDatabase(new UserRole()
				{
					RoleId = createAdminRole.Id,
					UserId = applicationUser.Id
				});
				return new GeneralResponse(true, "Account created");
			}

			//check user roles
			var checkUserRole = await dbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
			SystemRole response = new SystemRole();
			if (checkUserRole is null)
			{
				response = await AddToDatabase(new SystemRole() { Name = Constants.User });
				await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
			}
			else
			{
				await AddToDatabase(new UserRole() { RoleId= checkUserRole.Id, UserId= applicationUser.Id });
			}
			return new GeneralResponse(true, "Account created");

		}

		public async Task<LoginResponse> SignInAsync(Login user)
		{
			if (user is null) return new LoginResponse(false, "Model is empty");
			var appUser = await FindUserByEmail(user.Email);
			if (appUser is null) return new LoginResponse(false, "user not found");

			//verify password
			if (!BCrypt.Net.BCrypt.Verify(user.Password, appUser.Password))
				return new LoginResponse(false, " Email or Password not valid");
			var getUserRole = await FindUserRole(appUser.Id);
			if (getUserRole is null) return new LoginResponse(false, "user role not found");

			var getRoleName = await FindRoleName(getUserRole.Id);
			if (getRoleName is null) return new LoginResponse(false, "user role not found");

			//generate token

			string jwtToken = GenerateToken(appUser, getRoleName!.Name!);
			string refreshToken = GenerateRefreshToken();

			//find user for refreshtoken
			var findUser  = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ =>_.UserId == appUser.Id);
			if (findUser is not null)
			{
				findUser!.Token = refreshToken;
				await dbContext.SaveChangesAsync();
			}
			else
			{
				await AddToDatabase( new RefreshTokenInfo() { Token = refreshToken, UserId = appUser.Id });
			}
			return new LoginResponse (true ,"Login success", jwtToken, refreshToken);
		}

		public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
		{
			if (token is null) return new LoginResponse(false, "Model is empty");
			var findToken = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
			if (findToken is null) return new LoginResponse(false, "Refresh token is required");

			//get user details 
			var user = await dbContext.Users.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
			if (user is null) return new LoginResponse(false, " Refresh token could not be generated because user not found");

			var userRole = await FindUserRole(user.Id);
			var roleName = await FindRoleName(userRole.Id);
			string jwtToken = GenerateToken(user , roleName!.Name!);
			string refreshToken = GenerateRefreshToken();

			var updateRefreshToken = await dbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ =>_.UserId == user.Id);
			if (updateRefreshToken is null) return new LoginResponse(false, "Refresh token could not be generated because user has not sign in"); 

			updateRefreshToken.Token = refreshToken;
			await dbContext.SaveChangesAsync();
			return new LoginResponse(true, "Token Refresh success", jwtToken , refreshToken);	
		}
		private async Task<ApplicationUser> FindUserByEmail(string email) =>
			await dbContext.Users
			.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));
		private async Task<T> AddToDatabase<T>(T model)
		{
			var result = dbContext.Add(model!);
			await dbContext.SaveChangesAsync();
			return (T)result.Entity;
		}

		private string GenerateToken(ApplicationUser user, string role)
		{
			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.Key!));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
			var userClaims = new[]
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.Name!),
				new Claim(ClaimTypes.Email, user.Email!),
				new Claim(ClaimTypes.Role, role!)

			};

			var token = new JwtSecurityToken(
				issuer:config.Value.Issuer,
				audience:config.Value.Audience,
				claims:userClaims,
				expires:DateTime.Now.AddDays(1),
				signingCredentials:credentials);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}

		private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

		private async Task<UserRole> FindUserRole(int userId) => await dbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);
		private async Task<SystemRole> FindRoleName(int roleId) => await dbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);
		
	}
}
