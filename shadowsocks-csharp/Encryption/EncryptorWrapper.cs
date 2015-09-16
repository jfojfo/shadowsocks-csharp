using System;
using System.Collections.Generic;
using Shadowsocks.Controller;

namespace Shadowsocks.Encryption
{
    public class EncryptorWrapper
        : IEncryptor
    {
        private IEncryptor mRealEncryptor;
        private Random mRandom = new Random();
        private const int SIZE_ENCRYPTED_LEN = 8;
        private byte[] mLastBuffer = new byte[0];

        public EncryptorWrapper(IEncryptor encryptor)
        {
            mRealEncryptor = encryptor;
        }

        public void Encrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Logging.Log(LogLevel.Debug, "e:begin=======================================");
            int len1 = mRandom.Next(11, 20);
            Logging.Log(LogLevel.Debug, "e:===>len1:" + len1);
            int len2 = mRandom.Next(11,26);
            Logging.Log(LogLevel.Debug, "e:===>len2:" + len2);

            int encrypted_len = 0;
            mRealEncryptor.Encrypt(buf, length, outbuf, out encrypted_len);

            string base64str = Convert.ToBase64String(outbuf, 0, encrypted_len);
            byte[] encrypted_buf = System.Text.Encoding.Default.GetBytes(base64str);
            encrypted_len = encrypted_buf.Length;
            Logging.Log(LogLevel.Debug, "e:===>encrypted len:" + encrypted_len);
            if (encrypted_len + len1 + len2 + SIZE_ENCRYPTED_LEN > outbuf.Length)
            {
                Logging.Log(LogLevel.Error, "encrypt outbuf not enough " + (encrypted_len + len1 + len2 + SIZE_ENCRYPTED_LEN));
            }
            Array.Copy(encrypted_buf, 0, outbuf, len1 + len2 + SIZE_ENCRYPTED_LEN, encrypted_len);

            byte[] tmpBytes = new byte[4];
            int tmpLen = encrypted_len;
            for (int i = 0; i < 4; ++i)
            {
                tmpBytes[3 - i] = (byte)(tmpLen & 0xFF);
                tmpLen = tmpLen >> 8;
            }
            string tmpStr = Convert.ToBase64String(tmpBytes);
            Logging.Log(LogLevel.Debug, "e:===>encrypted len str:" + tmpStr);
            byte[] tmpB64Bytes = System.Text.Encoding.Default.GetBytes(tmpStr);
            Array.Copy(tmpB64Bytes, 0, outbuf, len1 + len2, tmpB64Bytes.Length);
            Logging.Log(LogLevel.Debug, "e:===>decrypted len:" + length);

            outbuf[0] = (byte)(len1 + 'A');
            for (int i = 1; i < len1; ++i)
            {
                outbuf[i] = (byte)mRandom.Next('A', 'Z'+1);
            }
            outbuf[len1] = (byte)(len2 + 'A');
            for (int i = 1; i < len2; ++i)
            {
                outbuf[len1+i] = (byte)mRandom.Next('A','Z'+1);
            }

            outlength = len1 + len2 + SIZE_ENCRYPTED_LEN + encrypted_len;
            Logging.Log(LogLevel.Debug, "e:end=========================================");
        }

        public void Decrypt(byte[] buf, int length, byte[] outbuf, out int outlength)
        {
            Logging.Log(LogLevel.Debug, "d:begin=======================================");
            if (buf != null && length > 0)
            {
                byte[] newBuf = new byte[mLastBuffer.Length + length];
                Array.Copy(mLastBuffer, 0, newBuf, 0, mLastBuffer.Length);
                Array.Copy(buf, 0, newBuf, mLastBuffer.Length, length);
                mLastBuffer = newBuf;
            }

            outlength = doDecrypt(outbuf, 0);
            Logging.Log(LogLevel.Debug, "d:end=========================================");
        }

        private int doDecrypt(byte[] outbuf, int outlength)
        {
            byte[] buf = mLastBuffer;
            if (buf.Length == 0)
                return outlength;

            int len1 = buf[0] - 'A';
            Logging.Log(LogLevel.Debug, "d:===>len1:" + len1);
            if (buf.Length <= len1)
            {
                Logging.Log(LogLevel.Debug, "d:===>need more data...");
                return outlength;
            }

            int len2 = buf[len1] - 'A';
            Logging.Log(LogLevel.Debug, "d:===>len2:" + len2);
            int pos = len1 + len2;
            if (buf.Length < pos + SIZE_ENCRYPTED_LEN)
            {
                Logging.Log(LogLevel.Debug, "d:===>need more data...");
                return outlength;
            }

            string tmpStr = System.Text.Encoding.ASCII.GetString(buf, pos, SIZE_ENCRYPTED_LEN);
            byte[] encrypted_len_bytes = Convert.FromBase64String(tmpStr);
            int encrypted_len = 0;
            for (int i = 0; i < 4; ++i)
            {
                encrypted_len = encrypted_len << 8;
                encrypted_len = encrypted_len | encrypted_len_bytes[i];
            }
            Logging.Log(LogLevel.Debug, "d:===>encrypted_len:" + encrypted_len);
            Logging.Log(LogLevel.Debug, "e:===>encrypted len str:" + tmpStr);
            pos += SIZE_ENCRYPTED_LEN;
            if (buf.Length < pos + encrypted_len)
            {
                Logging.Log(LogLevel.Debug, "d:===>need more data...");
                return outlength;
            }

            byte[] decrypted_data = Convert.FromBase64String(System.Text.Encoding.ASCII.GetString(buf, pos, encrypted_len));

            int decrypted_len = 0;
            byte[] decrypted_data2 = new byte[decrypted_data.Length + 1024];
            mRealEncryptor.Decrypt(decrypted_data, decrypted_data.Length, decrypted_data2, out decrypted_len);
            Logging.Log(LogLevel.Debug, "d:===>decrypted_len:" + decrypted_len);
            Array.Copy(decrypted_data2, 0, outbuf, outlength, decrypted_len);

            outlength += decrypted_len;
            pos += encrypted_len;

            mLastBuffer = new byte[buf.Length - pos];
            Array.Copy(buf, pos, mLastBuffer, 0, mLastBuffer.Length);

            return doDecrypt(outbuf, outlength);
        }

        public void Reset()
        {
        }

        public void Dispose()
        {
        }
    }
}
