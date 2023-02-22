using System;
using System.Numerics; // BigInteger
using System.Collections.Generic;

namespace P4
{
    class Program
    {
        public static BigInteger[] calculateRSAparameters(string[] args)
        {
           
            int p_e = Convert.ToInt32(args[0]);
            int p_c = Convert.ToInt32(args[1]);
            int q_e = Convert.ToInt32(args[2]);
            int q_c = Convert.ToInt32(args[3]);
            BigInteger p = BigInteger.Subtract(BigInteger.Pow(2, p_e), p_c);
            BigInteger q = BigInteger.Subtract(BigInteger.Pow(2, q_e), q_c);
            BigInteger N = BigInteger.Multiply(p , q);
            BigInteger plainText =  BigInteger.Parse(args[5]);
            BigInteger cipher = BigInteger.Parse(args[4]);
            BigInteger e = 65537;
            BigInteger phi_N = BigInteger.Multiply((p-1) , (q-1));
            BigInteger[] EEA = ExtendedEuclideanAlgorithm(phi_N, e);
            BigInteger d = EEA[2];
            /*igInteger rem = 0;
            BigInteger qoutiont = BigInteger.DivRem(BigInteger.Multiply(e, d), phi_N, out rem );
            Console.WriteLine(rem);*/
            BigInteger[] result = new BigInteger[] {e, d, N, plainText, cipher};
            
            return result;
        }

        public static BigInteger encrypt(BigInteger m, BigInteger e, BigInteger N)
        {
            BigInteger c = BigInteger.ModPow(m, e, N);
            return c;

        }

        public static BigInteger decrypt(BigInteger c, BigInteger d, BigInteger N)
        {
            BigInteger m = BigInteger.ModPow(c, d, N);
            return m;
        }

        public static BigInteger[] ExtendedEuclideanAlgorithm(BigInteger phi_N, BigInteger e)
        {
           BigInteger[] result = new BigInteger[3];
           if (e == 0)
           {
            result[0] = phi_N;
            result[1] = 1;
            result[2] = 0;
            return result;
           }

           if (phi_N < e) 
           { 
                BigInteger temp = e;
                e = phi_N;
                phi_N = temp;
           }

           BigInteger rem = 0; 
           BigInteger q = 0; 
           BigInteger x1 = 0;
           BigInteger y1 = 1;
           BigInteger x2 = 1;
           BigInteger y2 = 0;
           BigInteger x = 0, y = 0;
           while (e > 0)
            {
                q = BigInteger.DivRem(phi_N, e, out rem);
                x = BigInteger.Subtract(x2, BigInteger.Multiply(x1, q));
                y = BigInteger.Subtract(y2, BigInteger.Multiply(y1, q));
                x2 = x1;
                y2 = y1;
                x1 = x;
                y1 = y;
                phi_N = e;
                e = rem;
            }
            result[0] = phi_N;
            result[1] = x2;
            result[2] = y2;
            return result;
        }

        static void Main(string[] args)
        {
            /*
            * useful help for RSA encrypt/decrypt: https://www.di-mgt.com.au/rsa_alg.html
            * help with extended euclidean algorithm: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
            * 
            */

            // Some other helpful links: https://gist.github.com/GiveThanksAlways/00a5c4e911795992268b0c998e2ec487

            // dotnet run 254 1223 251 1339 66536047120374145538916787981868004206438539248910734713495276883724693574434582104900978079701174539167102706725422582788481727619546235440508214694579  1756026041

            BigInteger[] parameters = calculateRSAparameters(args);
            Console.WriteLine(decrypt(parameters[4], parameters[1] , parameters[2]) + "," + encrypt(parameters[3] , parameters[0] , parameters[2]) );
        }
    }
}