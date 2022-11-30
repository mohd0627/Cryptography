using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Collections;
namespace P2
{
    class Program
    {
        // This function will help us get the input from the command line
        public static string getInputFromCommandLine(string[] args)
        {
            // get the input from the command line
            string input = "";
            if (args.Length == 1)
            {
                input = args[0]; // Gets the first string after the 'dotnet run' command
            }
            else
            {
                Console.WriteLine("Not enough or too many inputs provided after 'dotnet run' ");
            }
            return input;
        }

        public static string ComputeMd5Hash(string message, string salt)
	    {
	        using (MD5 md5 = MD5.Create())
	        {
	            byte[] messageByteArray = Encoding.UTF8.GetBytes(message);
                byte saltByte = Convert.ToByte(salt, 16);
                byte[] saltedByteArray = new byte[messageByteArray.Length + 1];

                for (int i=0; i< saltedByteArray.Length; i++){
                    if (i < saltedByteArray.Length - 1){
                        saltedByteArray[i] = messageByteArray[i];
                    }

                    else if (i == saltedByteArray.Length - 1){
                        saltedByteArray[i] = saltByte;
                    }
                }

	            byte[] hash = md5.ComputeHash(saltedByteArray);

                string hashedString = BitConverter.ToString(hash).Replace("-", "");

	            return hashedString;
	        }
        }

        public static string RandomPasswordGenerator(int length)
        {

            Random random = new Random();
            string alphanumeric_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var passwordChars = new char[length];
            for (int i = 0; i < passwordChars.Length; i++)
            {
                passwordChars[i] = alphanumeric_characters[random.Next(alphanumeric_characters.Length)];
            }

            string password = new String(passwordChars);
            return password;


        }


        public static string BirthdayAttack(int length, string salt)
        {
            Hashtable PasswordsHashTable = new Hashtable();
            string password1 = RandomPasswordGenerator(length);
            string hashedPassword1 = ComputeMd5Hash(password1, salt).Substring(0, 10);
            PasswordsHashTable.Add(hashedPassword1, password1);
            //Console.WriteLine(password1);
            string result = "";

            bool flag = false;
            while (flag == false){

                string password2 = RandomPasswordGenerator(length);
                string hashedPassword2 = ComputeMd5Hash(password2, salt).Substring(0, 10);
                //Console.WriteLine(password2);
                if(PasswordsHashTable.ContainsKey(hashedPassword2)){
                    if (!String.Equals( (String)PasswordsHashTable[hashedPassword2], password2)){
                        flag = true;
                        password1 = (string) PasswordsHashTable[hashedPassword2];
                        result = password1 + "," + password2;
                    }
                }

                else{
                    PasswordsHashTable.Add(hashedPassword2, password2);
                }
                
            }

            return result;
        }

        static void Main(string[] args)
        {
            // Some helpful hints:
            // The main idea is to concateneate the salt to a random string, 
            // then feed that into the hashFunction, 
            // then keep track of those salted hashes until you find a matching pair of salted hashes, 
            // then print the solution which is the two strings that gave the matching salted hashes
            // NOTE: When I say salted hashes, I mean that you salted the password and then fed it into the hashFunction. So it is the hash of the password+salt (in this case "+" means concatenated together into one)

            // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.md5?view=netcore-3.1
            // hint: what does Create() do?

            // optional hint: review converting a string into a byte array (byte[]) and the reverse, converting a byte array (byte[]) into a string BitConverter.ToString(exampleByteArray).Replace("-", " ");

            // This code will convert a string to a byte array

            //string example = RandomPasswordGenerator(10);
            //byte[] exampleByteArray = Encoding.UTF8.GetBytes(example);
            string salt = getInputFromCommandLine(args);
            //string s1 = example + salt;
            //Console.WriteLine(RandomPasswordGenerator(10)+ salt);
            //Console.WriteLine(ComputeMd5Hash(s1).Substring(0, 10));

            // passwords have to be made only using alphanumeric characters, so you can make random passwords using any of the characters in the string provided below (note: The starter code doesn't include lowercase just for simplicity but you can include lowercase as well. )
            //string alphanumeric_characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

            // optional hint: What data structure can you use to store the salted hashes that has a really fast lookup time of O(1) (constant) ?
            // You don't have to use this data structure, but it will make your code run fast. The System.Collections.Generic libary is a good place to start

            // TODO: Employ the Birthday Paradox to find a collision in the MD5 hash function

            // These were given as en example, you are going to have to find two passwords that have matching salted hashes with your code and then output them for the autograder to see

            Console.WriteLine(BirthdayAttack(10, salt));
        }

    }
}