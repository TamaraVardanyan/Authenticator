using Authenticator.Model;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Authenticator.Services
{
    public class UserService
    {
        private readonly IConfiguration _configuration;
        public UserService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        /// <summary>
        /// Authenticates a user based on the provided username and password.
        /// If authentication is successful, generates a jwt token for the user.
        /// </summary>
        /// <param name="user">The user object containing the username and password to be authenticated.</param>
        /// <returns>
        /// A jwt token if authentication is successful;
        /// "wrong password" if the password is incorrect;
        /// an empty string if the user does not exist.
        /// </returns>
        public string Authenticate(User user)
        {
            // Retrieve the hashed password associated with the provided username
            var data = DataBase.ReadFromJsonFile(user.UserName);

            if (data != null)
            {
                // Hash the provided password using SHA-256
                using (SHA256 sha256 = SHA256.Create())
                {
                    byte[] passwordBytes = Encoding.UTF8.GetBytes(user.Password);

                    byte[] hashedBytes = sha256.ComputeHash(passwordBytes);

                    string hashedPassword = Convert.ToBase64String(hashedBytes);

                    // Compare the hashed password with the stored hashed password
                    if (data == hashedPassword)
                    {
                        var tokenHandler = new JwtSecurityTokenHandler();
                        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
                        var tokenDescriptor = new SecurityTokenDescriptor
                        {
                            Subject = new ClaimsIdentity(new Claim[]
                            {
                                new Claim(ClaimTypes.Name, user.UserName)
                            }),
                            Expires = DateTime.UtcNow.AddMinutes(30),
                            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                        };

                        // Create the JWT token
                        var token = tokenHandler.CreateToken(tokenDescriptor);
                        string userToken = tokenHandler.WriteToken(token);

                        return userToken;
                    }
                    else
                    {
                        return "wrong password";
                    }
                }
            }
            else
            {
                return string.Empty;
            }
        }

        /// <summary>
        /// Registers a new user by writing their information to the JSON file database.
        /// </summary>
        /// <param name="user">The user object containing the username and password to be registered.</param>
        public void Register(User user)
        {
            DataBase.WriteToJsonFile(user);
        }
    }
}