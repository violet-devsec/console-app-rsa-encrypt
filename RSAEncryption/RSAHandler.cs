using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Numerics;

namespace RSAEncryption
{
    public static class RSAHandler
    {
        public static byte[] EncryptUsingPrivateKey(string message)
        {
            byte[] data = Encoding.ASCII.GetBytes(message);

            RSACryptoServiceProvider rsaPrivate = new RSACryptoServiceProvider();

            rsaPrivate.FromXmlString("<RSAKeyValue><Modulus>tGF2VC12FkDS2hIrI+O6za7GCqIov8BMvqruio7qQPXr8m1mKmC64wUSbj/TyHW9Cc4T0TzfsrBboMf+euyUx1udgfa+LfzRqzHi5S4PcVkB02m4Gg1oUJiyHc/zRGF1Cmwpok3iuHEMO0umIpVsQoHNKfFnAPRJZf8zUeRmsxE=</Modulus><Exponent>AQAB</Exponent><P>2WD/tCoHei1V+IckxMEUWTKvCO3XfbxEbfRKRRpure8yRd4VZXjQCVk7ErNi8pdfLGNP5mvUp+4sPlySIpUEjw==</P><Q>1G2ungPc60S0C3H1HDTbbR/ya6n26es3s4dyhN4AUlq/IXXJJ9alYGHiPvu9QLiSP9lTyzVpyLE2VPAOR3reXw==</Q><DP>vpJiOiGqonsCZrqcCn43B6f+ebaB9/JIj5jeT8zHgWc1TLlRSr9qqvd2aYOo2ILKZlC+qISaT4rncNiZKQY5kw==</DP><DQ>v9vcRT0p75eaoWeoQHSA5htfgNv+dSELqusfhF9ZnQf27kqKhp+3t8hQZiBJusW42U/4/WTdiPR9JNO3odmYMw==</DQ><InverseQ>VeogMAy66hEAJv7k4G4H3J/FcVoPdNmmd3dYGMroy7YJpYJFq66BuxAHN++CEjbboqmsL1xU++bCnufpmh+zEw==</InverseQ><D>SpX+UsJVkNAPH8Lheb6hsIjzNNRmmxtN4I1Xg42iyWemv6CC3UUQIe0n+NSFot8kYpiG0z8jlISd7rajwHpw7eh3nEXwr61bCo+sm7butAhOTw734q/QM0pz/tx1IqRCKN858O6BNfchkI6al66v3MtY7loSUOMWesG0K3DV0s0=</D></RSAKeyValue>");

            if (data == null)
                throw new ArgumentNullException("data");
            if (rsaPrivate.PublicOnly)
                throw new InvalidOperationException("Private key is not loaded");

            int maxDataLength = (rsaPrivate.KeySize / 8) - 6;
            if (data.Length > maxDataLength)
                throw new ArgumentOutOfRangeException("data", string.Format(
                    "Maximum data length for the current key size ({0} bits) is {1} bytes (current length: {2} bytes)",
                    rsaPrivate.KeySize, maxDataLength, data.Length));


            // Add 4 byte padding to the data, and convert to BigInteger struct
            BigInteger numData = GetBig(AddPadding(data));

            RSAParameters rsaParams = rsaPrivate.ExportParameters(true);
            BigInteger D = GetBig(rsaParams.D);
            BigInteger Modulus = GetBig(rsaParams.Modulus);
            BigInteger encData = BigInteger.ModPow(numData, D, Modulus);

            return encData.ToByteArray();
        }

        public static byte[] DecryptUsingPublicKey(byte[] cipherData)
        {
            RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider();

            rsaPublic.FromXmlString("<RSAKeyValue><Modulus>tGF2VC12FkDS2hIrI+O6za7GCqIov8BMvqruio7qQPXr8m1mKmC64wUSbj/TyHW9Cc4T0TzfsrBboMf+euyUx1udgfa+LfzRqzHi5S4PcVkB02m4Gg1oUJiyHc/zRGF1Cmwpok3iuHEMO0umIpVsQoHNKfFnAPRJZf8zUeRmsxE=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>");

            if (cipherData == null)
                throw new ArgumentNullException("cipherData");

            BigInteger numEncData = new BigInteger(cipherData);

            RSAParameters rsaParams = rsaPublic.ExportParameters(false);
            BigInteger Exponent = GetBig(rsaParams.Exponent);
            BigInteger Modulus = GetBig(rsaParams.Modulus);

            BigInteger decData = BigInteger.ModPow(numEncData, Exponent, Modulus);

            byte[] data = decData.ToByteArray();
            byte[] result = new byte[data.Length - 1];
            Array.Copy(data, result, result.Length);
            result = RemovePadding(result);

            Array.Reverse(result);
            return result;
        }
        private static BigInteger GetBig(byte[] data)
        {
            byte[] inArr = (byte[])data.Clone();
            Array.Reverse(inArr);  // Reverse the byte order
            byte[] final = new byte[inArr.Length + 1];  // Add an empty byte at the end, to simulate unsigned BigInteger (no negatives!)
            Array.Copy(inArr, final, inArr.Length);

            return new BigInteger(final);
        }

        // Add 4 byte random padding, first bit *Always On*
        private static byte[] AddPadding(byte[] data)
        {
            Random rnd = new Random();
            byte[] paddings = new byte[4];
            rnd.NextBytes(paddings);
            paddings[0] = (byte)(paddings[0] | 128);

            byte[] results = new byte[data.Length + 4];

            Array.Copy(paddings, results, 4);
            Array.Copy(data, 0, results, 4, data.Length);
            return results;
        }

        private static byte[] RemovePadding(byte[] data)
        {
            byte[] results = new byte[data.Length - 4];
            Array.Copy(data, results, results.Length);
            return results;
        }
    }
}
