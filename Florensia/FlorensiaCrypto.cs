using System;

namespace FlorensiaProxy.Cryptography
{
    public class FlorensiaCrypto
    {
        private int CryptoSeed { get; set; }
        private int StaticSeed = 0x0048473C;

        public FlorensiaCrypto() { }

        public void SetKey(int key)
        {
            this.CryptoSeed = key;
        }

        public FlorensiaCrypto(int Seed)
        {
            this.CryptoSeed = Seed;
        }

        public byte[] EncryptDecrypt(int crypto_flag, byte[] buff, int offset)
        {
            if (buff.Length - offset <= 0 || buff.Length == 0)
                return new byte[0];

            byte[] result = new byte[buff.Length];
            Buffer.BlockCopy(buff, 0, result, 0, offset);
            int Seed;

            if (crypto_flag == 1)
            {
                Seed = StaticSeed;
                for (int i = 0; i < buff.Length - offset; ++i)
                {
                    result[i + offset] = (byte)(BitConverter.GetBytes(Seed)[1] ^ buff[i + offset]);
                    Seed = 0x002BA339 * (Seed + result[i + offset]) + 0x02CAD2B5;
                }
            }
            else if (crypto_flag == 2)
            {
                Seed = this.CryptoSeed;
                for (int i = 0; i < buff.Length - offset; ++i)
                {
                    result[i + offset] = (byte)(BitConverter.GetBytes(Seed)[1] ^ buff[i + offset]);
                    Seed = 0x008E9A99 * (Seed + result[i + offset]) + 0x00685B24;
                }
            }
            else
            {
                for (int i = 0; i < buff.Length - offset; ++i)
                    result[i + offset] = (byte)(~buff[i + offset]);
            }

            return result;
        }
    }
}
