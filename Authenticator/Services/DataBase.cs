using Authenticator.Model;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Authenticator.Services
{
    public class DataBase
    {
        // Path to the json file used as the database
        private static string FilePath = "DataBase.json";

        /// <summary>
        /// Writes a new user's data to the json file.
        /// Adds the user's username and hashed password to the existing data and updates the file.
        /// </summary>
        /// <param name="user">The user object containing the username and password to be added.</param>
        public static void WriteToJsonFile(User user)
        {
            // Read the existing data from the json file
            Dictionary<string, string> data = ReadFromJsonFile();

            // Hash the password using SHA-256
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] passwordBytes = Encoding.UTF8.GetBytes(user.Password);
                byte[] hashedBytes = sha256.ComputeHash(passwordBytes);
                string hashedPassword = Convert.ToBase64String(hashedBytes);
                data.Add(user.UserName, hashedPassword);
            }
            string jsonString = JsonSerializer.Serialize(data);

            // Write the json string to the file
            File.WriteAllText(FilePath, jsonString);
        }

        /// <summary>
        /// Reads a user's hashed password from the json file.
        /// Looks up the hashed password associated with the given username.
        /// </summary>
        /// <param name="key">The username for which the password is requested.</param>
        /// <returns>The hashed password associated with the given username, or null if not found.</returns>
        public static string ReadFromJsonFile(string key)
        {
            ReadFromJsonFile().TryGetValue(key, out var value);
            return value;
        }

        /// <summary>
        /// Reads all user data from the json file.
        /// Deserializes the json file content into a dictionary.
        /// </summary>
        /// <returns>A dictionary containing all usernames and their associated hashed passwords.</returns>
        static Dictionary<string, string> ReadFromJsonFile()
        {
            string jsonString = File.ReadAllText(FilePath);
            var result = new Dictionary<string, string>();
            if (!string.IsNullOrWhiteSpace(jsonString))
            {
                result = JsonSerializer.Deserialize<Dictionary<string, string>>(jsonString);
            }
            return result;
        }
    }
}