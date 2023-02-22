using System;
using System.Security.Cryptography; // Aes
using System.Numerics; // BigInteger
using System.IO;

namespace P3
{
    class Program
    {
        public static string[] getInputFromCommandLine(string[] args)
        {
            // get the input from the command line
            string cipher = "";
            string plainText = "";
            string IV = "";

            IV = args[0];
            cipher = args[7];
            plainText = args[8];
            string[] input = new string[]{IV, cipher, plainText};

            return input;
        }


        public static byte[] calculateKey(string[] args)
        {
           
            int N_e = Convert.ToInt32(args[3]);
            int N_c = Convert.ToInt32(args[4]);
            int x = Convert.ToInt32(args[5]);
            BigInteger g_y = BigInteger.Parse(args[6]);
            BigInteger N = BigInteger.Subtract(BigInteger.Pow(2, N_e), N_c);
            BigInteger sharedKey = BigInteger.ModPow(g_y, x, N);
            byte[] key = sharedKey.ToByteArray();
            return key;
        }

        static byte[] get_bytes_from_string(string input)
        {
            var input_split = input.Split(' ');
            byte[] inputBytes = new byte[input_split.Length];
            int i = 0;
            foreach (string item in input_split)
            {
                inputBytes.SetValue(Convert.ToByte(item, 16), i);
                i++;
            }
            return inputBytes;
        }


static string DecryptStringFromBytes_Aes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }

        static byte[] EncryptStringToBytes_Aes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;

            // Create an Aes object
            // with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            // Return the encrypted bytes from the memory stream.
            return encrypted;
        }

        static void Main(string[] args)
        {
            // Make sure you are familiar with the System.Numerics.BigInteger class and how to use some of the functions it has (Parse, Pow, ModPow, Subtract, ToByteArray, etc.)
            
            // optional hint: for encryptiong/ decryption with AES, use google or another search engine to find the microsoft documentation on Aes (google this--> System.Security.Cryptography.Aes)

            // optional hint: here is an example of how to convert the IV input string to a byte array https://gist.github.com/GiveThanksAlways/df9e0fa9e7ea04d51744df6a325f7530

            // you will be using BigInteger functions for almost all, if not all mathmatical operations. (Pow, ModPow, Subtract)
            // N = 2^(N_e) - N_c (this calculation needs to be done using BigInteger.Pow and BigInteger.Subtract)

            // Diffie-Hellman key is g^(xy) mod N. In the input you are given g_y which is g^y. So to make the key you need to perform g_y^(x) using the BigInteger class
            // key = g_y^(x) mod N (this calculation needs to be done using BigInteger.ModPow)

            // you can convert a BigInteger into a byte array using the BigInteger.ToByteArray() function/method
            
            /*
            dotnet run "A2 2D 93 61 7F DC 0D 8E C6 3E A7 74 51 1B 24 B2" 251 465 255 1311 2101864342 8995936589171851885163650660432521853327227178155593274584417851704581358902 "F2 2C 95 FC 6B 98 BE 40 AE AD 9C 07 20 3B B3 9F F8 2F 6D 2D 69 D6 5D 40 0A 75 45 80 45 F2 DE C8 6E C0 FF 33 A4 97 8A AF 4A CD 6E 50 86 AA 3E DF" AfYw7Z6RzU9ZaGUloPhH3QpfA1AXWxnCGAXAwk3f6MoTx
            */
            string[] inputStrings = getInputFromCommandLine(args);
            byte[] key = calculateKey(args);
            byte[] IV = get_bytes_from_string(inputStrings[0]);
            byte[] cipher = get_bytes_from_string(inputStrings[1]);
            string decryptedCipher = DecryptStringFromBytes_Aes(cipher, key, IV);
            byte[] encryptedPlainText = EncryptStringToBytes_Aes(inputStrings[2], key, IV);
            string encryptedString = BitConverter.ToString(encryptedPlainText).Replace("-", " ");

            Console.WriteLine(decryptedCipher + "," + encryptedString);

        }
    }
}