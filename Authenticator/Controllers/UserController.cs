using Authenticator.Model;
using Authenticator.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Authenticator.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly UserService _userService;
        public UserController(UserService userService)
        {
            _userService = userService;
        }

        /// <summary>
        /// Authenticates the user and returns a jwt token if successful.
        /// </summary>
        /// <param name="user">The user object containing the username and password to be authenticated.</param>
        /// <returns>
        /// An IActionResult containing the jwt token if authentication is successful;
        /// A bad request response if the username or password is incorrect.
        /// </returns>
        [HttpPost("Login")]
        [AllowAnonymous]
        public IActionResult Login(User user)
        {
            var token = _userService.Authenticate(user);
            if (token == null || token == string.Empty)
            {
                return BadRequest(new { message = "UserName or Password is incorrect" });
            }
            return Ok(token);
        }

        /// <summary>
        /// Registers a new user by writing their information to the json file database.
        /// </summary>
        /// <param name="user">The user object containing the username and password to be registered.</param>
        [HttpPost("Register")]
        [AllowAnonymous]
        public void Register(User user)
        {
            _userService.Register(user);
        }
    }
}
