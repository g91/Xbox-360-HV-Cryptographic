using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Generic;


//this is a c-sharp remake of the of the Python script released on this GitHub 
//https://github.com/GoobyCorp/Xbox-360-Crypto/blob/master/MemCrypto.py 
//credits = ["tydye81", "teir1plus2", "no-op", "juv", "GoobyCorp"]


class Program
{
    static bool EnableDebug = false; // Default: no debug logs

    static readonly byte[] ALL_55_KEY = Enumerable.Repeat((byte)0x55, 0x10).ToArray();
    static readonly int GF2_IV = 0;
    static readonly int GF2_POLY = 0x87;
    static readonly int HVEX_ADDR = 0x01B5;
    static readonly int HV_17559_TABLE_ADDR = 0x10878;
    static readonly int SRAM_CKSM_PAGE_SIZE = 0x80;
    static readonly byte[] _1BL_KEY = "DD88AD0C9ED669E7B56794FB68563EFA".HexStringToBytes();

    // MASTER RSA VALUES
    static BigInteger MASTER_N = BigInteger.Parse("E1322F1DE92AD64B494455CB05173F6671A964A415536E2B680C40F54FDA808F19B82CD0D7E964B2224C56DE03E2462F946F4FFFAD4588" +
        "CF78CEED1CE5FD0F80533AE97043EAD1D12E39880C3CAEEBFDA5ACA3A69445E542EF269D5459952D252945B0169BEF788FB1EAE548AC1A" +
        "C3C878899708DE24D1ED04D0555079199527", System.Globalization.NumberStyles.HexNumber);
    static readonly int MASTER_E = 0x10001;

    static ushort[] GF2_TAB = null!;

    static ulong CreateMask(int n) => (1UL << n) - 1UL;

    static readonly ulong UINT8_MASK = CreateMask(8);
    static readonly ulong UINT16_MASK = CreateMask(16);
    static readonly ulong UINT32_MASK = CreateMask(32);
    static readonly ulong UINT36_MASK = CreateMask(36);
    static readonly ulong UINT64_MASK = CreateMask(64);
    static readonly BigInteger UINT128_MASK = (BigInteger.One << 128) - 1;

    static byte[] ReadFile(string filename) => File.ReadAllBytes(filename);
    static void WriteFile(string filename, byte[] data) => File.WriteAllBytes(filename, data);

    static ushort Rotr(ushort n, int d, int b)
    {
        int shift = b - d;
        ushort mask = (ushort)((1 << b) - 1);
        uint val = (uint)n;
        val = (ushort)(((val >> d) | ((val << shift) & mask)) & 0xFFFF);
        return (ushort)val;
    }

    static void DebugLog(string message)
    {
        if (EnableDebug)
            Console.WriteLine(message);
    }

    static byte[] SxorU32(byte[] s1, byte[] s2)
    {
        DebugLog($"[DEBUG] SxorU32: s1.Length={s1.Length}, s2.Length={s2.Length}");
        if (s1.Length != s2.Length)
        {
            DebugLog("SxorU32 Error: Length mismatch!");
            DebugLog($"s1 length: {s1.Length}");
            DebugLog($"s2 length: {s2.Length}");
            throw new Exception("s1 and s2 must be same size");
        }

        byte[] result = new byte[s1.Length];
        for (int i = 0; i < s1.Length; i += 4)
        {
            uint a = BitConverter.ToUInt32(s1, i);
            uint b = BitConverter.ToUInt32(s2, i);
            uint c = a ^ b;
            Array.Copy(BitConverter.GetBytes(c), 0, result, i, 4);
        }

        return result;
    }

    static byte[] SandU32(byte[] s1, byte[] s2)
    {
        DebugLog($"[DEBUG] SandU32: s1.Length={s1.Length}, s2.Length={s2.Length}");
        if (s1.Length != s2.Length) throw new Exception("s1 and s2 must be same size");
        byte[] result = new byte[s1.Length];

        for (int i = 0; i < s1.Length; i += 4)
        {
            uint a = BitConverter.ToUInt32(s1, i);
            uint b = BitConverter.ToUInt32(s2, i);
            uint c = a & b;
            Array.Copy(BitConverter.GetBytes(c), 0, result, i, 4);
        }

        return result;
    }

    static byte[] SxorB(byte[] s1, byte[] s2)
    {
        DebugLog($"[DEBUG] SxorB: s1.Length={s1.Length}, s2.Length={s2.Length}");
        if (s1.Length != s2.Length) throw new Exception("s1 and s2 must be same size");
        byte[] result = new byte[s1.Length];
        for (int i = 0; i < s1.Length; i++)
        {
            result[i] = (byte)(s1[i] ^ s2[i]);
        }
        return result;
    }

    static byte[] ReadChunk(byte[] data, int offset, int size)
    {
        if (offset + size > data.Length)
            throw new Exception("ReadChunk requested beyond end of data");
        byte[] chunk = new byte[size];
        Array.Copy(data, offset, chunk, 0, size);
        return chunk;
    }

    static IEnumerable<byte[]> ReadChunks(byte[] data, int offset, int size)
    {
        if ((data.Length - offset) % size != 0) throw new Exception("data must be evenly divisible by size");
        for (int i = offset; i < data.Length; i += size)
        {
            yield return ReadChunk(data, i, size);
        }
    }

    static ushort[] GenerateGf2Table(int iv, int poly)
    {
        ushort[] tab = new ushort[256];
        for (int i = 0; i < 256; i++)
        {
            int crc = iv;
            int c = i << 8;
            for (int j = 0; j < 8; j++)
            {
                if (((crc ^ c) & 0x8000) != 0)
                    crc = (crc << 1) ^ poly;
                else
                    crc <<= 1;
                c <<= 1;
            }
            tab[i] = (ushort)(crc & 0xFFFF);
        }
        return tab;
    }

    static byte[] PackSecEngKeys(byte[] key, byte[] buffer, int offset, int length)
    {
        int cycle = 0;
        while (length > 0)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] cycleBytes = BitConverter.GetBytes(cycle);
                if (BitConverter.IsLittleEndian) Array.Reverse(cycleBytes);

                sha1.TransformBlock(key, 0, key.Length, key, 0);
                sha1.TransformBlock(cycleBytes, 0, cycleBytes.Length, cycleBytes, 0);
                sha1.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                byte[] digest = sha1.Hash!;
                int sublen = 0x14;
                if (length < 0x14)
                    sublen = length;

                byte[] chunk = ReadChunk(buffer, offset, sublen);
                for (int i = 0; i < sublen; i++)
                {
                    chunk[i] = (byte)(chunk[i] ^ digest[i]);
                }

                Array.Copy(chunk, 0, buffer, offset, sublen);

                offset += sublen;
                length -= sublen;
                cycle += 1;
            }
        }
        return buffer;
    }

    static byte[] BigIntegerToBigEndian(BigInteger value, int size = 0)
    {
        byte[] bytes = value.ToByteArray(isBigEndian: false);
        Array.Reverse(bytes);
        if (size > 0 && bytes.Length < size)
        {
            byte[] padded = new byte[size];
            Array.Copy(bytes, 0, padded, size - bytes.Length, bytes.Length);
            return padded;
        }
        return bytes;
    }

    class MemoryCrypto : IDisposable
    {
        public byte[] white_key = Array.Empty<byte>();
        public byte[] aes_key = Array.Empty<byte>();
        public byte[] hash_key = Array.Empty<byte>();

        public MemoryCrypto(byte[] wkey, byte[] akey, byte[] hkey)
        {
            if (wkey.Length != 16 || akey.Length != 16 || hkey.Length != 16)
                throw new Exception("Keys must be 16 bytes each");
            white_key = wkey;
            aes_key = akey;
            hash_key = hkey;
        }

        public void Dispose() { }

        public void Reset()
        {
            white_key = Array.Empty<byte>();
            aes_key = Array.Empty<byte>();
            hash_key = Array.Empty<byte>();
        }

        public int SramOffsetToHvOffset(int sram_offset) => (sram_offset / 2) * SRAM_CKSM_PAGE_SIZE;
        public int SramSizeToHvSize(int sram_size) => SramOffsetToHvOffset(sram_size);

        BigInteger GetTweak1(BigInteger n)
        {
            BigInteger of = (n >> 128) & UINT36_MASK;
            n &= UINT128_MASK;

            int i = 0;
            while (of > 0)
            {
                int index = (int)(of & 0xFF);
                n ^= (BigInteger)GF2_TAB[index] << (i * 8);
                of >>= 8;
                i += 1;
            }
            return n & UINT128_MASK;
        }

        byte[] GetTweak0(long address)
        {
            BigInteger key = BigIntegerFromBigEndian(white_key);

            BigInteger value = key << 36;
            long addr = address >> 4;

            for (int i = 0; i < 64; i++)
            {
                if (((addr >> i) & 1) == 1)
                {
                    value ^= (key << i);
                }
            }

            BigInteger tweak = GetTweak1(value);

            // Convert tweak to exactly 16 bytes big-endian
            byte[] val = tweak.ToByteArray(isUnsigned: true, isBigEndian: false);
            if (val.Length > 16)
                throw new Exception("Tweak is longer than 16 bytes, unexpected!");

            byte[] tmp = new byte[16];
            for (int i = 0; i < val.Length; i++)
                tmp[16 - val.Length + i] = val[val.Length - 1 - i];

            return tmp;
        }

        long FixAddress(long address)
        {
            if (0 <= address && address <= 0x40000)
            {
                return address | (0x200000000L * (address / 0x10000));
            }
            else
            {
                return address;
            }
        }

        private byte[] AesEcbTransform(byte[] key, byte[] data, bool encrypt)
        {
            if (data.Length != 16)
                throw new Exception("AesEcbTransform data length must be 16 bytes");
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (ICryptoTransform transform = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor())
                {
                    byte[] result = transform.TransformFinalBlock(data, 0, data.Length);
                    if (result.Length != 16)
                        throw new Exception("AES transform did not return 16 bytes");
                    return result;
                }
            }
        }

        public byte[] EncryptBlock(byte[] dec_data, int offset, int size, long address = 0, bool offset_is_address = false)
        {
            if (offset_is_address) address = offset;

            byte[] block = ReadChunk(dec_data, offset, size);
            byte[] tweak = GetTweak0(address);

            DebugLog("[DEBUG] EncryptBlock:");
            DebugLog($" - block size: {block.Length}");
            DebugLog($" - tweak size: {tweak.Length}");

            byte[] xored = SxorU32(block, tweak);
            byte[] enc_data = AesEcbTransform(aes_key, xored, false);
            DebugLog($" - After AesEcbTransform (EncryptBlock): enc_data size={enc_data.Length}");

            enc_data = SxorU32(enc_data, tweak);
            return enc_data;
        }

        public byte[] DecryptBlock(byte[] enc_data, int offset, int size, long address = 0, bool offset_is_address = false)
        {
            if (offset_is_address) address = offset;

            byte[] block = ReadChunk(enc_data, offset, size);
            byte[] tweak = GetTweak0(address);

            DebugLog("[DEBUG] DecryptBlock:");
            DebugLog($" - block size: {block.Length}");
            DebugLog($" - tweak size: {tweak.Length}");

            byte[] xored = SxorU32(block, tweak);
            byte[] dec_data = AesEcbTransform(aes_key, xored, true);
            DebugLog($" - After AesEcbTransform (DecryptBlock): dec_data size={dec_data.Length}");

            dec_data = SxorU32(dec_data, tweak);
            return dec_data;
        }

        public byte[] Encrypt(byte[] hv_data_dec, int offset, int size, long address = 0, bool offset_is_address = false)
        {
            if (offset_is_address) address = offset;
            if (size % 16 != 0) throw new Exception("Size must be divisible by 16");

            hv_data_dec = ReadChunk(hv_data_dec, offset, size);

            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < size; i += 16)
                {
                    byte[] block = EncryptBlock(hv_data_dec, i, 16, FixAddress(address + i), false);
                    ms.Write(block, 0, 16);
                }
                return ms.ToArray();
            }
        }

        public byte[] Decrypt(byte[] hv_data_enc, int offset, int size, long address = 0, bool offset_is_address = false)
        {
            if (offset_is_address) address = offset;
            if (size % 16 != 0) throw new Exception("Size must be divisible by 16");
            if (hv_data_enc.Length < offset + size)
                throw new Exception("Requested size exceeds hv_data_enc length");
            if ((hv_data_enc.Length % 16) != 0)
                throw new Exception("Encrypted data not multiple of 16 in length");

            hv_data_enc = ReadChunk(hv_data_enc, offset, size);

            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < size; i += 16)
                {
                    byte[] block = DecryptBlock(hv_data_enc, i, 16, FixAddress(address + i), false);
                    ms.Write(block, 0, 16);
                }
                return ms.ToArray();
            }
        }

        public byte[] EncryptAndCalcChecksums(byte[] hv_data_dec, int offset, int size, long address = 0, bool offset_is_address = false)
        {
            if (offset_is_address) address = offset;
            hv_data_dec = ReadChunk(hv_data_dec, offset, size);
            byte[] hv_data_enc = Encrypt(hv_data_dec, 0, size, address, false);
            return CalcSramChecksums(hv_data_dec, hv_data_enc, 0, size);
        }

        public ushort CalcSramChecksum(byte[] data)
        {
            int length = data.Length;
            ushort cksm = 0;
            int rot_val = 1;
            for (int i = 0; i < length / 2; i++)
            {
                ushort v = (ushort)((data[i * 2] << 8) | data[i * 2 + 1]);
                ushort r = Rotr(v, rot_val, 16);
                cksm ^= r;
                rot_val = ((i + 1) / 4) + 1;
            }
            return (ushort)(cksm & 0xFFFF);
        }

        public byte[] CalcSramChecksums(byte[] hv_data_dec, byte[] hv_data_enc, int offset, int size)
        {
            if (size % SRAM_CKSM_PAGE_SIZE != 0) throw new Exception("Hashes require data divisible by 0x80");

            hv_data_dec = ReadChunk(hv_data_dec, offset, size);
            hv_data_enc = ReadChunk(hv_data_enc, offset, size);

            byte[] mask = RepeatKey(hash_key, hv_data_dec.Length / 0x10);
            byte[] masked = SandU32(hv_data_enc, mask);
            hv_data_dec = SxorU32(masked, hv_data_dec);

            int num_cksm_pages = size / SRAM_CKSM_PAGE_SIZE;
            using (MemoryStream ms = new MemoryStream())
            {
                for (int i = 0; i < num_cksm_pages; i++)
                {
                    byte[] page = ReadChunk(hv_data_dec, i * SRAM_CKSM_PAGE_SIZE, SRAM_CKSM_PAGE_SIZE);
                    ushort c = CalcSramChecksum(page);
                    ushort net_c = (ushort)System.Net.IPAddress.HostToNetworkOrder((short)c);
                    ms.Write(BitConverter.GetBytes(net_c), 0, 2);
                }
                return ms.ToArray();
            }
        }

        public byte[] GetChecksumChunkBySramOffsetAndSize(byte[] hv_data_dec, byte[] hv_data_enc, int sram_offset, int sram_size)
        {
            int hv_offs = SramOffsetToHvOffset(sram_offset);
            int hv_size = SramSizeToHvSize(sram_size);
            return CalcSramChecksums(hv_data_dec, hv_data_enc, hv_offs, hv_size);
        }

        public byte[] CalcSram(byte[] hv_data_dec)
        {
            byte[] hv_data_enc = Encrypt(hv_data_dec, 0, 0x40000, 0, false);
            return CalcSramChecksums(hv_data_dec, hv_data_enc, 0, 0x40000);
        }

        public byte[] CalcHash1Digest(byte[] hv_data_dec, byte[] salt)
        {
            salt = ReadChunk(salt, 0, 0x10);
            using (SHA1 sha = SHA1.Create())
            {
                sha.TransformBlock(salt, 0, salt.Length, salt, 0);
                sha.TransformBlock(hv_data_dec, 0x34, 0x40, hv_data_dec, 0x34);
                sha.TransformBlock(hv_data_dec, 0x78, 0xFF88, hv_data_dec, 0x78);
                sha.TransformBlock(hv_data_dec, 0x100C0, 0x40, hv_data_dec, 0x100C0);
                sha.TransformBlock(hv_data_dec, 0x10350, 0x5F70, hv_data_dec, 0x10350);
                sha.TransformBlock(hv_data_dec, 0x16EA0, 0x9160, hv_data_dec, 0x16EA0);
                sha.TransformBlock(hv_data_dec, 0x20000, 0xFFFF, hv_data_dec, 0x20000);
                sha.TransformBlock(hv_data_dec, 0x30000, 0xFFFF, hv_data_dec, 0x30000);
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                byte[] hash = sha.Hash!;
                return hash.Skip(0xE).Take(6).ToArray();
            }
        }

        public byte[] CalcHash2Digest(byte[] hv_data_dec, byte[] salt, int hvex_addr)
        {
            salt = ReadChunk(salt, 0, 0x10);

            byte[] hv_salt_dec = RepeatKey(salt, 8);
            long hv_hash_addr = ((long)hvex_addr << 16) | 0x7C00000000L + 0x400;

            using (SHA1 sha = SHA1.Create())
            {
                var chunk1 = EncryptAndCalcChecksums(hv_salt_dec, 0, hv_salt_dec.Length, hv_hash_addr);
                sha.TransformBlock(chunk1, 0, chunk1.Length, chunk1, 0);

                sha.TransformBlock(hv_data_dec, 0x34, 0xC, hv_data_dec, 0x34);
                var enc1 = Encrypt(hv_data_dec, 0x40, 0x30, 0x40, true);
                sha.TransformBlock(enc1, 0, enc1.Length, enc1, 0);

                sha.TransformBlock(hv_data_dec, 0x70, 4, hv_data_dec, 0x70);
                sha.TransformBlock(hv_data_dec, 0x78, 8, hv_data_dec, 0x78);

                var encChecks1 = EncryptAndCalcChecksums(hv_data_dec, 0x80, 0xFF80, 0x80, true);
                sha.TransformBlock(encChecks1, 0, encChecks1.Length, encChecks1, 0);

                var enc2 = Encrypt(hv_data_dec, 0x100C0, 0x40, 0x100C0, true);
                sha.TransformBlock(enc2, 0, enc2.Length, enc2, 0);

                var enc3 = Encrypt(hv_data_dec, 0x10350, 0x30, 0x10350, true);
                sha.TransformBlock(enc3, 0, enc3.Length, enc3, 0);

                var encChecks2 = EncryptAndCalcChecksums(hv_data_dec, 0x10380, 0x5F00, 0x10380, true);
                sha.TransformBlock(encChecks2, 0, encChecks2.Length, encChecks2, 0);

                var enc4 = Encrypt(hv_data_dec, 0x16280, 0x40, 0x16280, true);
                sha.TransformBlock(enc4, 0, enc4.Length, enc4, 0);

                var enc5 = Encrypt(hv_data_dec, 0x16EA0, 0x60, 0x16EA0, true);
                sha.TransformBlock(enc5, 0, enc5.Length, enc5, 0);

                var encChecks3 = EncryptAndCalcChecksums(hv_data_dec, 0x16F00, 0x9100, 0x16F00, true);
                sha.TransformBlock(encChecks3, 0, encChecks3.Length, encChecks3, 0);

                var encChecks4 = EncryptAndCalcChecksums(hv_data_dec, 0x20000, 0x10000, 0x20000, true);
                sha.TransformBlock(encChecks4, 0, encChecks4.Length, encChecks4, 0);

                var encChecks5 = EncryptAndCalcChecksums(hv_data_dec, 0x30000, 0x10000, 0x30000, true);
                sha.TransformBlock(encChecks5, 0, encChecks5.Length, encChecks5, 0);

                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return sha.Hash!;
            }
        }

        public byte[] CalcKeyBlob(byte[] blob_nonce)
        {
            byte[] key_blob = new byte[0x80];
            Array.Copy(blob_nonce, 0, key_blob, 1, Math.Min(blob_nonce.Length, 20));
            byte[] emptySha1 = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709".HexStringToBytes();
            Array.Copy(emptySha1, 0, key_blob, 0x15, emptySha1.Length);
            key_blob[0x4F] = 1;
            Array.Copy(white_key, 0, key_blob, 0x50, 0x10);
            Array.Copy(aes_key, 0, key_blob, 0x60, 0x10);
            Array.Copy(hash_key, 0, key_blob, 0x70, 0x10);

            key_blob = PackSecEngKeys(ReadChunk(key_blob, 0x1, 0x14), key_blob, 0x15, 0x6B);
            key_blob = PackSecEngKeys(ReadChunk(key_blob, 0x15, 0x6B), key_blob, 1, 0x14);

            // Perform raw RSA: ciphertext = key_blob^e mod n, no padding
            if (key_blob.Length != 0x80)
                throw new Exception("Key blob must be exactly 128 bytes.");

            // Convert from big-endian to little-endian for BigInteger
            byte[] reversed = new byte[key_blob.Length];
            Array.Copy(key_blob, reversed, key_blob.Length);
            Array.Reverse(reversed);

            // Create BigInteger from little-endian unsigned data
            BigInteger plaintext = new BigInteger(reversed, isUnsigned: true, isBigEndian: false);

            // Compute ciphertext
            BigInteger ciphertext = BigInteger.ModPow(plaintext, MASTER_E, MASTER_N);

            // Convert back to big-endian
            byte[] cipherBytes = ciphertext.ToByteArray(isUnsigned: true, isBigEndian: false);
            Array.Reverse(cipherBytes);

            // Pad if needed
            if (cipherBytes.Length < 0x80)
            {
                byte[] padded = new byte[0x80];
                Buffer.BlockCopy(cipherBytes, 0, padded, 0x80 - cipherBytes.Length, cipherBytes.Length);
                cipherBytes = padded;
            }

            return cipherBytes;
        }

        public byte[] Calc100F0(byte[] hv_data_dec, int tbl_addr)
        {
            byte[] hv_data_enc = Encrypt(hv_data_dec, 0, 0x40000, 0, false);

            using (SHA1 sha = SHA1.Create())
            {
                for (int i = 0; i < 6; i++)
                {
                    int o = tbl_addr + (i * 8);
                    uint u_strt_addr = BitConverter.ToUInt32(hv_data_dec, o);
                    uint u_stop_addr = BitConverter.ToUInt32(hv_data_dec, o + 4);

                    ulong a_strt_addr = (ulong)((u_strt_addr + 0x7F) & 0xFFFFFF80);
                    ulong a_stop_addr = (ulong)(u_stop_addr & 0xFFFFFF80);

                    if (a_strt_addr < a_stop_addr)
                    {
                        int sram_offs = (int)((a_strt_addr / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);
                        int sram_size = (int)(((a_stop_addr - a_strt_addr) / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);

                        byte[] chunk = GetChecksumChunkBySramOffsetAndSize(hv_data_dec, hv_data_enc, sram_offs, sram_size);
                        sha.TransformBlock(chunk, 0, chunk.Length, chunk, 0);
                    }
                }
                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return sha.Hash!.Take(0x10).ToArray();
            }
        }
    }

    static byte[] RepeatKey(byte[] key, int count)
    {
        byte[] result = new byte[key.Length * count];
        for (int i = 0; i < count; i++)
        {
            Array.Copy(key, 0, result, i * key.Length, key.Length);
        }
        return result;
    }

    static BigInteger BigIntegerFromBigEndian(byte[] data)
    {
        byte[] tmp = new byte[data.Length];
        Array.Copy(data, tmp, data.Length);
        Array.Reverse(tmp);
        return new BigInteger(tmp, isUnsigned: true, isBigEndian: false);
    }

    static byte[] LittleEndianToBigEndian(byte[] data)
    {
        byte[] tmp = new byte[data.Length];
        Array.Copy(data, tmp, data.Length);
        Array.Reverse(tmp);
        return tmp;
    }

    static byte[] BigIntegerToLittleEndian(BigInteger val)
    {
        return val.ToByteArray(isBigEndian: false);
    }

    static void Main(string[] args)
    {
        // Check command line args for --debug
        // If present, enable debug logs
        if (args.Contains("--debug"))
        {
            EnableDebug = true;
        }

        GF2_TAB = GenerateGf2Table(GF2_IV, GF2_POLY);

        if (args.Length > 0 && args[0] == "calculate")
        {
            byte[] hv_data_dec = ReadFile("bin/HV_17559_Cleaned.bin");

            byte[] white_key = ALL_55_KEY;
            byte[] aes_key = ALL_55_KEY;
            byte[] hash_key = ALL_55_KEY;

            Console.WriteLine("W: " + BitConverter.ToString(white_key).Replace("-", ""));
            Console.WriteLine("A: " + BitConverter.ToString(aes_key).Replace("-", ""));
            Console.WriteLine("H: " + BitConverter.ToString(hash_key).Replace("-", ""));
            Console.WriteLine();

            byte[] blob_nonce = Encoding.ASCII.GetBytes("testtest");
            int hvex_addr = 0xB00B;
            byte[] hv_salt = "892BB9F952C7759392A12A3184E0358E".HexStringToBytes();

            using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            {
                Console.WriteLine("Hash 1: " + BitConverter.ToString(mem.CalcHash1Digest(hv_data_dec, hv_salt)!).Replace("-", ""));
            }
            Console.WriteLine();

            using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            {
                Console.WriteLine("Hash 2: " + BitConverter.ToString(mem.CalcHash2Digest(hv_data_dec, hv_salt, hvex_addr)!).Replace("-", ""));
            }
            Console.WriteLine();

            //NOT WORKING 
            //using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            //{
            //    Console.WriteLine("Key blob: " + BitConverter.ToString(mem.CalcKeyBlob(blob_nonce)).Replace("-", ""));
            //}
            Console.WriteLine();
        }
        else if (args.Length > 0 && args[0] == "test")
        {
            byte[] keys = ReadFile("bin/keys.bin");
            if (keys.Length < 0x30)
                throw new Exception("keys.bin must contain at least 48 bytes (16 bytes per key)");

            byte[] white_key = keys.Take(0x10).ToArray();
            byte[] aes_key = keys.Skip(0x10).Take(0x10).ToArray();
            byte[] hash_key = keys.Skip(keys.Length - 0x10).ToArray();

            if (white_key.Length != 16 || aes_key.Length != 16 || hash_key.Length != 16)
                throw new Exception("Extracted keys are not 16 bytes each. Check keys.bin.");

            byte[] hv_enc = ReadFile("bin/HV.enc.bin");
            if ((hv_enc.Length % 16) != 0)
                throw new Exception("HV.enc.bin length is not multiple of 16 bytes. Can't decrypt properly.");

            using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            {
                Console.WriteLine("[DEBUG] Starting decryption test...");
                byte[] dec = mem.Decrypt(hv_enc, 0, hv_enc.Length, 0, true);
                WriteFile("HV.dec.bin", dec);
            }
        }

        Console.WriteLine("Done!");
    }
}

public static class Extensions
{
    public static byte[] HexStringToBytes(this string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string length");
        byte[] bytes = new byte[hex.Length / 2];
        for (int i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = byte.Parse(hex.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
        }
        return bytes;
    }
}
