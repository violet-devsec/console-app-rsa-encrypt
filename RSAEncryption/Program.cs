using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RSAEncryption
{
    class Program
    {
        static void Main(string[] args)
        {

            string message = "Hi, this is secret!";

            var encryptedBinary = RSAHandler.EncryptUsingPrivateKey(message);

            var encryptedString = Encoding.ASCII.GetString(encryptedBinary);

            Console.WriteLine("Encrypted String: " + encryptedString);

            var decryptedBinary = RSAHandler.DecryptUsingPublicKey(encryptedBinary);

            var decryptedString = Encoding.ASCII.GetString(decryptedBinary);

            Console.WriteLine("Decrypted String: " + decryptedString);

            Console.ReadKey();
        }
    }
}
