using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Generic;

<<<<<<< HEAD
=======

>>>>>>> 7fac7492533b71b5c3f086f9268fc315a6e5bac6
//this is a c-sharp remake of the of the Python script released on this GitHub 
//https://github.com/GoobyCorp/Xbox-360-Crypto/blob/master/MemCrypto.py 
//credits = ["tydye81", "teir1plus2", "no-op", "juv", "GoobyCorp"]

<<<<<<< HEAD
=======

>>>>>>> 7fac7492533b71b5c3f086f9268fc315a6e5bac6
class Program
{
    static bool EnableDebug = false; // Debug logs are disabled by default

    // Default file paths
    static readonly string DefaultBinFolder = "bin";
    static readonly string DefaultKeyFilePath = Path.Combine("bin", "keys.bin");
    static readonly string DefaultHvDecFilePath = Path.Combine("bin", "hv_dec.bin");
    static readonly string DefaultHvEncFilePath = Path.Combine("bin", "hv_enc.bin");
    static readonly string DefaultOutputFolder = Path.Combine("bin", "output");

    // Constants
    public static readonly byte[] ALL_55_KEY = Enumerable.Repeat((byte)0x55, 0x10).ToArray();
    public static readonly int GF2_IV = 0;
    public static readonly int GF2_POLY = 0x87;
    public static readonly int SRAM_CKSM_PAGE_SIZE = 0x80;
    public static readonly byte[] _1BL_KEY = "DD88AD0C9ED669E7B56794FB68563EFA".HexStringToBytes();

    // MASTER RSA VALUES
    public static readonly BigInteger MASTER_N = BigInteger.Parse(
        "E1322F1DE92AD64B494455CB05173F6671A964A415536E2B680C40F54FDA808F19B82CD0D7E964B2224C56DE03E2462F946F4FFFAD4588" +
        "CF78CEED1CE5FD0F80533AE97043EAD1D12E39880C3CAEEBFDA5ACA3A69445E542EF269D5459952D252945B0169BEF788FB1EAE548AC1A" +
        "C3C878899708DE24D1ED04D0555079199527", System.Globalization.NumberStyles.HexNumber);
    public static readonly int MASTER_E = 0x10001;

    public static ushort[] GF2_TAB = null!;

    // Bit masks
    public static readonly ulong UINT8_MASK = CreateMask(8);
    public static readonly ulong UINT16_MASK = CreateMask(16);
    public static readonly ulong UINT32_MASK = CreateMask(32);
    public static readonly ulong UINT36_MASK = CreateMask(36);
    public static readonly ulong UINT64_MASK = CreateMask(64);
    public static readonly BigInteger UINT128_MASK = (BigInteger.One << 128) - 1;

    // Ensure bin directory exists
    static void EnsureDefaultDirectories()
    {
        string[] directories = { DefaultBinFolder, DefaultOutputFolder };
        foreach (string dir in directories)
        {
            if (!Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
                Console.WriteLine($"Created directory: {dir}");
            }
        }
    }

    // Generate default 555 keys if they don't exist
    static void EnsureDefaultKeys()
    {
        if (!File.Exists(DefaultKeyFilePath))
        {
            byte[] defaultKeys = new byte[48]; // 16 bytes each for white_key, aes_key, and hash_key
            for (int i = 0; i < defaultKeys.Length; i++)
            {
                defaultKeys[i] = 0x55;
            }
            File.WriteAllBytes(DefaultKeyFilePath, defaultKeys);
            Console.WriteLine($"Created default 555 keys at: {DefaultKeyFilePath}");
        }
    }

    static ulong CreateMask(int n) => (1UL << n) - 1UL;

    static byte[] ReadFile(string filename) => File.ReadAllBytes(filename);
    static void WriteFile(string filename, byte[] data) => File.WriteAllBytes(filename, data);

    public static void DebugLog(string message)
    {
        if (EnableDebug)
            Console.WriteLine(message);
    }

    public static byte[] ReadChunk(byte[] data, int offset, int size)
    {
        if (offset + size > data.Length)
            throw new ArgumentOutOfRangeException("Requested offset and size exceed the data length.");
        byte[] chunk = new byte[size];
        Array.Copy(data, offset, chunk, 0, size);
        return chunk;
    }

    public static ushort Rotr(ushort n, int d, int b)
    {
        int shift = b - d;
        ushort mask = (ushort)((1 << b) - 1);
        uint val = (uint)n;
        val = (ushort)(((val >> d) | ((val << shift) & mask)) & 0xFFFF);
        return (ushort)val;
    }

    public static byte[] SxorU32(byte[] s1, byte[] s2)
    {
        DebugLog($"[DEBUG] SxorU32: s1.Length={s1.Length}, s2.Length={s2.Length}");
        if (s1.Length != s2.Length)
        {
            DebugLog("SxorU32 Error: Length mismatch!");
            throw new Exception("s1 and s2 must be the same size");
        }

        byte[] result = new byte[s1.Length];
        for (int i = 0; i < s1.Length; i += 4)
        {
            if (i + 4 > s1.Length) break;
            uint a = BitConverter.ToUInt32(s1, i);
            uint b = BitConverter.ToUInt32(s2, i);
            uint c = a ^ b;
            Array.Copy(BitConverter.GetBytes(c), 0, result, i, 4);
        }

        return result;
    }

    public static byte[] SandU32(byte[] s1, byte[] s2)
    {
        DebugLog($"[DEBUG] SandU32: s1.Length={s1.Length}, s2.Length={s2.Length}");
        if (s1.Length != s2.Length) throw new Exception("s1 and s2 must be the same size");

        byte[] result = new byte[s1.Length];
        for (int i = 0; i < s1.Length; i += 4)
        {
            if (i + 4 > s1.Length) break;
            uint a = BitConverter.ToUInt32(s1, i);
            uint b = BitConverter.ToUInt32(s2, i);
            uint c = a & b;
            Array.Copy(BitConverter.GetBytes(c), 0, result, i, 4);
        }

        return result;
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

    public static byte[] PackSecEngKeys(byte[] key, byte[] buffer, int offset, int length)
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
                int sublen = Math.Min(length, digest.Length);

                byte[] tempChunk = ReadChunk(buffer, offset, sublen);
                for (int i = 0; i < sublen; i++)
                {
                    tempChunk[i] ^= digest[i];
                }

                Array.Copy(tempChunk, 0, buffer, offset, sublen);

                offset += sublen;
                length -= sublen;
                cycle++;
            }
        }
        return buffer;
    }

    public static byte[] RepeatKey(byte[] key, int count)
    {
        byte[] result = new byte[key.Length * count];
        for (int i = 0; i < count; i++)
        {
            Array.Copy(key, 0, result, i * key.Length, key.Length);
        }
        return result;
    }

    public static BigInteger BigIntegerFromBigEndian(byte[] data)
    {
        byte[] tmp = new byte[data.Length];
        Array.Copy(data, tmp, data.Length);
        Array.Reverse(tmp);
        return new BigInteger(tmp, isUnsigned: true, isBigEndian: false);
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
                if (index >= GF2_TAB.Length)
                {
                    DebugLog($"GetTweak1 Warning: GF2_TAB index {index} out of bounds. Skipping.");
                    break;
                }
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

        public static void VerboseDebugLog(string message)
        {
            if (EnableDebug)
            {
                string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");
                Console.WriteLine($"[{timestamp}] {message}");
            }
        }


        public byte[] Calc100F0(byte[] hv_data_dec, int fixed_addr)
        {
            // First ensure we can read all the regions we need
            int[] requiredOffsets = new int[]
            {
                fixed_addr,      // Base offset
                fixed_addr + 8,  // First pair
                fixed_addr + 16, // Second pair
                fixed_addr + 24, // Third pair
                fixed_addr + 32, // Fourth pair
                fixed_addr + 40, // Fifth pair
                fixed_addr + 48  // Last readable offset
            };

            // Check if we can read all required offsets
            foreach (int offset in requiredOffsets)
            {
                if (offset + 8 > hv_data_dec.Length)
                {
                    throw new ArgumentException($"Hypervisor too small. Required size: 0x{offset + 8:X}, actual size: 0x{hv_data_dec.Length:X}");
                }
            }

            byte[] hv_data_enc = Encrypt(hv_data_dec, 0, 0x40000, 0, false);

            using (SHA1 sha = SHA1.Create())
            {
                for (int i = 0; i < 6; i++)
                {
                    int o = fixed_addr + (i * 8);

                    uint u_strt_addr = BitConverter.ToUInt32(hv_data_dec, o);
                    uint u_stop_addr = BitConverter.ToUInt32(hv_data_dec, o + 4);

                    ulong a_strt_addr = (ulong)((u_strt_addr + 0x7F) & 0xFFFFFF80);
                    ulong a_stop_addr = (ulong)(u_stop_addr & 0xFFFFFF80);

                    if (a_strt_addr < a_stop_addr)
                    {
                        try
                        {
                            int sram_offs = (int)((a_strt_addr / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);
                            int sram_size = (int)(((a_stop_addr - a_strt_addr) / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);

                            // Validate the calculated offsets
                            if (sram_offs < 0 || sram_size < 0 || sram_offs + sram_size > hv_data_dec.Length)
                            {
                                DebugLog($"[WARNING] Invalid SRAM range at index {i}: offset=0x{sram_offs:X}, size=0x{sram_size:X}");
                                continue;
                            }

                            byte[] chunk = GetChecksumChunkBySramOffsetAndSize(hv_data_dec, hv_data_enc, sram_offs, sram_size);
                            if (chunk != null && chunk.Length > 0)
                            {
                                sha.TransformBlock(chunk, 0, chunk.Length, chunk, 0);
                            }
                        }
                        catch (Exception ex)
                        {
                            DebugLog($"[WARNING] Error processing chunk {i}: {ex.Message}");
                            continue;
                        }
                    }
                }

                sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
                return sha.Hash!.Take(0x10).ToArray();
            }
        }
        static byte[] Handle100F0Generation(byte[] hv_dec, int fixed_addr)
        {
            // Always use 555 keys for 100F0 calculation
            using (var mem = new MemoryCrypto(ALL_55_KEY, ALL_55_KEY, ALL_55_KEY))
            {
                DebugLog("[DEBUG] Calculating 100F0 hash using 555 keys...");
                byte[] hash100F0 = mem.Calc100F0(hv_dec, fixed_addr);
                return mem.Inject100F0Hash(hv_dec, hash100F0, fixed_addr);
            }
        }


        //public byte[] Calc100F0(byte[] hv_data_dec, int fixed_addr)
        //{
        //    byte[] hv_data_enc = Encrypt(hv_data_dec, 0, 0x40000, 0, false);

        //    using (SHA1 sha = SHA1.Create())
        //    {
        //        for (int i = 0; i < 6; i++)
        //        {
        //            int o = fixed_addr + (i * 8);
        //            if (o + 8 > hv_data_dec.Length)
        //            {
        //                DebugLog($"Calc100F0 Warning: Offset {o} + 8 exceeds hv_data_dec length {hv_data_dec.Length}. Skipping.");
        //                continue;
        //            }

        //            uint u_strt_addr = BitConverter.ToUInt32(hv_data_dec, o);
        //            uint u_stop_addr = BitConverter.ToUInt32(hv_data_dec, o + 4);

        //            ulong a_strt_addr = (ulong)((u_strt_addr + 0x7F) & 0xFFFFFF80);
        //            ulong a_stop_addr = (ulong)(u_stop_addr & 0xFFFFFF80);

        //            if (a_strt_addr < a_stop_addr)
        //            {
        //                int sram_offs = (int)((a_strt_addr / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);
        //                int sram_size = (int)(((a_stop_addr - a_strt_addr) / (ulong)SRAM_CKSM_PAGE_SIZE) * 2);

        //                byte[] chunk = GetChecksumChunkBySramOffsetAndSize(hv_data_dec, hv_data_enc, sram_offs, sram_size);
        //                sha.TransformBlock(chunk, 0, chunk.Length, chunk, 0);
        //            }
        //        }
        //        sha.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
        //        return sha.Hash!.Take(0x10).ToArray();
        //    }
        //}

        public byte[] Inject100F0Hash(byte[] hv_data_dec, byte[] hash, int fixed_addr)
        {
            if (hash.Length != 16)
                throw new ArgumentException("Hash must be exactly 16 bytes.");

            if (fixed_addr + hash.Length > hv_data_dec.Length)
                throw new ArgumentException("Injection address is out of bounds.");

            byte[] modified_hv = (byte[])hv_data_dec.Clone();
            Array.Copy(hash, 0, modified_hv, fixed_addr, hash.Length);

            return modified_hv;
        }
    }

    // Command Handlers
    static void HandleCalculateCommand(string[] args)
    {
        string hvFile = DefaultHvDecFilePath;
        string keysFile = DefaultKeyFilePath;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--hv" && i + 1 < args.Length)
            {
                hvFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--keys" && i + 1 < args.Length)
            {
                keysFile = args[i + 1];
                i++;
            }
        }

        if (!File.Exists(hvFile))
        {
            Console.WriteLine($"Error: Hypervisor file not found at {hvFile}");
            return;
        }

        // Ensure default keys exist
        EnsureDefaultKeys();

        byte[] hv_data_dec = ReadFile(hvFile);
        if (hv_data_dec.Length < 0x40000)
        {
            Console.WriteLine($"Error: Hypervisor file must be at least 0x40000 bytes. Current size: {hv_data_dec.Length}");
            return;
        }

        //byte[] white_key = ALL_55_KEY;
        //byte[] aes_key = ALL_55_KEY;
        //byte[] hash_key = ALL_55_KEY;

        //if (File.Exists(keysFile))
        //{
        //    byte[] keys = ReadFile(keysFile);
        //    if (keys.Length >= 0x30)
        //    {
        //        white_key = keys.Take(0x10).ToArray();
        //        aes_key = keys.Skip(0x10).Take(0x10).ToArray();
        //        hash_key = keys.Skip(0x20).Take(0x10).ToArray();
        //    }
        //}

        byte[] white_key = ALL_55_KEY;
        byte[] aes_key = ALL_55_KEY;
        byte[] hash_key = ALL_55_KEY;

        Console.WriteLine("W: " + BitConverter.ToString(white_key).Replace("-", ""));
        Console.WriteLine("A: " + BitConverter.ToString(aes_key).Replace("-", ""));
        Console.WriteLine("H: " + BitConverter.ToString(hash_key).Replace("-", ""));
        Console.WriteLine();

        byte[] blob_nonce = Encoding.ASCII.GetBytes("testtest");
        int hvex_addr = 0x01B2;
        byte[] hv_salt = "0AA98663E24797B3DEFD22444F364004".HexStringToBytes();

        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            Console.WriteLine("Hash 1: " + BitConverter.ToString(mem.CalcHash1Digest(hv_data_dec, hv_salt)).Replace("-", ""));
        }
        Console.WriteLine();

        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            Console.WriteLine("Hash 2: " + BitConverter.ToString(mem.CalcHash2Digest(hv_data_dec, hv_salt, hvex_addr)).Replace("-", ""));
        }
        Console.WriteLine();

        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            Console.WriteLine("Key blob: " + BitConverter.ToString(mem.CalcKeyBlob(blob_nonce)).Replace("-", ""));
        }
        Console.WriteLine();
    }

    static void HandleDecryptCommand(string[] args)
    {
        string inputFile = DefaultHvEncFilePath;
        string outputFile = DefaultHvDecFilePath;
        string keysFile = DefaultKeyFilePath;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length)
            {
                inputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--output" && i + 1 < args.Length)
            {
                outputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--keys" && i + 1 < args.Length)
            {
                keysFile = args[i + 1];
                i++;
            }
        }

        if (!File.Exists(inputFile))
        {
            Console.WriteLine($"Error: Input file not found at {inputFile}");
            return;
        }

        // Ensure default keys exist
        EnsureDefaultKeys();

        byte[] white_key = ALL_55_KEY;
        byte[] aes_key = ALL_55_KEY;
        byte[] hash_key = ALL_55_KEY;

        if (File.Exists(keysFile))
        {
            byte[] keys = ReadFile(keysFile);
            if (keys.Length >= 0x30)
            {
                white_key = keys.Take(0x10).ToArray();
                aes_key = keys.Skip(0x10).Take(0x10).ToArray();
                hash_key = keys.Skip(0x20).Take(0x10).ToArray();
            }
        }

        byte[] hv_enc = ReadFile(inputFile);
        if ((hv_enc.Length % 16) != 0)
        {
            Console.WriteLine("Error: Encrypted hypervisor length is not multiple of 16 bytes. Can't decrypt properly.");
            return;
        }

        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            DebugLog("[DEBUG] Starting decryption...");
            byte[] dec = mem.Decrypt(hv_enc, 0, hv_enc.Length, 0, false);
            WriteFile(outputFile, dec);
            Console.WriteLine($"Decryption completed. Output written to {outputFile}");
        }
    }

    static void HandleEncryptCommand(string[] args)
    {
        string inputFile = DefaultHvDecFilePath;
        string outputFile = DefaultHvEncFilePath;
        string keysFile = DefaultKeyFilePath;

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length)
            {
                inputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--output" && i + 1 < args.Length)
            {
                outputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--keys" && i + 1 < args.Length)
            {
                keysFile = args[i + 1];
                i++;
            }
        }

        if (!File.Exists(inputFile))
        {
            Console.WriteLine($"Error: Input file not found at {inputFile}");
            return;
        }

        // Ensure default keys exist
        EnsureDefaultKeys();

        byte[] white_key = ALL_55_KEY;
        byte[] aes_key = ALL_55_KEY;
        byte[] hash_key = ALL_55_KEY;

        if (File.Exists(keysFile))
        {
            byte[] keys = ReadFile(keysFile);
            if (keys.Length >= 0x30)
            {
                white_key = keys.Take(0x10).ToArray();
                aes_key = keys.Skip(0x10).Take(0x10).ToArray();
                hash_key = keys.Skip(0x20).Take(0x10).ToArray();
            }
        }

        byte[] hv_dec = ReadFile(inputFile);
        if ((hv_dec.Length % 16) != 0)
        {
            Console.WriteLine("Error: Decrypted hypervisor length is not multiple of 16 bytes. Can't encrypt properly.");
            return;
        }

        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            DebugLog("[DEBUG] Starting encryption...");
            byte[] enc = mem.Encrypt(hv_dec, 0, hv_dec.Length, 0, false);
            WriteFile(outputFile, enc);
            Console.WriteLine($"Encryption completed. Output written to {outputFile}");
        }
    }

    static void HandleCashCommand(string[] args)
    {
        string inputFile = DefaultHvDecFilePath;
        string keysFile = DefaultKeyFilePath;
        string outputFolder = DefaultOutputFolder;

        // Parse command line arguments
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length)
            {
                inputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--keys" && i + 1 < args.Length)
            {
                keysFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--output" && i + 1 < args.Length)
            {
                outputFolder = args[i + 1];
                i++;
            }
        }

        try
        {
            // Check if input file exists and validate it
            if (!File.Exists(inputFile))
            {
                Console.WriteLine($"Error: Input hypervisor file not found at {inputFile}");
                Console.WriteLine($"Expected default path: {DefaultHvDecFilePath}");
                return;
            }

            byte[] hv_dec;
            try
            {
                hv_dec = ReadFile(inputFile);
                Console.WriteLine($"Successfully read hypervisor file: {inputFile} (Size: {hv_dec.Length:X} bytes)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading hypervisor file {inputFile}: {ex.Message}");
                return;
            }

            if (hv_dec.Length < 0x40000)
            {
                Console.WriteLine($"Error: Hypervisor file must be at least 0x40000 bytes. Current size: 0x{hv_dec.Length:X}");
                return;
            }

            if (hv_dec.Length % 16 != 0)
            {
                Console.WriteLine($"Error: Hypervisor file size must be a multiple of 16. Current size: 0x{hv_dec.Length:X}");
                return;
            }

            // Initialize keys
            byte[] white_key = new byte[16];
            byte[] aes_key = new byte[16];
            byte[] hash_key = new byte[16];

            // Read and process keys
            if (File.Exists(keysFile))
            {
                try
                {
                    byte[] keys = ReadFile(keysFile);
                    Console.WriteLine($"Read keys file: {keysFile} (Size: {keys.Length:X} bytes)");

                    if (keys.Length >= 0x30)
                    {
                        Array.Copy(keys, 0, white_key, 0, 16);
                        Array.Copy(keys, 16, aes_key, 0, 16);
                        Array.Copy(keys, 32, hash_key, 0, 16);
                    }
                    else
                    {
                        Console.WriteLine($"Warning: Keys file {keysFile} is too small ({keys.Length:X} bytes). Using default 555 keys.");
                        Array.Copy(ALL_55_KEY, white_key, 16);
                        Array.Copy(ALL_55_KEY, aes_key, 16);
                        Array.Copy(ALL_55_KEY, hash_key, 16);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Error reading keys file {keysFile}: {ex.Message}");
                    Console.WriteLine("Using default 555 keys.");
                    Array.Copy(ALL_55_KEY, white_key, 16);
                    Array.Copy(ALL_55_KEY, aes_key, 16);
                    Array.Copy(ALL_55_KEY, hash_key, 16);
                }
            }
            else
            {
                Console.WriteLine($"Warning: Keys file {keysFile} not found. Using default 555 keys.");
                Array.Copy(ALL_55_KEY, white_key, 16);
                Array.Copy(ALL_55_KEY, aes_key, 16);
                Array.Copy(ALL_55_KEY, hash_key, 16);
            }

            Console.WriteLine("Using keys:");
            Console.WriteLine("W: " + BitConverter.ToString(white_key).Replace("-", ""));
            Console.WriteLine("A: " + BitConverter.ToString(aes_key).Replace("-", ""));
            Console.WriteLine("H: " + BitConverter.ToString(hash_key).Replace("-", ""));
            Console.WriteLine();

            // Process the hypervisor
            Console.WriteLine("Processing hypervisor...");

            // Generate encrypted hypervisor
            Console.WriteLine("Encrypting hypervisor...");
            byte[] hv_enc;
            using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            {
                hv_enc = mem.Encrypt(hv_dec, 0, hv_dec.Length, 0, false);
                Console.WriteLine("Encryption completed.");
            }

            // Calculate SRAM checksums
            Console.WriteLine("Calculating SRAM checksums...");
            byte[] sram;
            using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
            {
                sram = mem.CalcSram(hv_dec);
                Console.WriteLine("SRAM checksums calculated.");
            }

            // Create output folder
            if (!Directory.Exists(outputFolder))
            {
                Directory.CreateDirectory(outputFolder);
                Console.WriteLine($"Created output folder: {outputFolder}");
            }

            // Write output files
            Console.WriteLine("Writing output files...");

            string keysOutputPath = Path.Combine(outputFolder, "keys.bin");
            byte[] keysCombined = new byte[48];
            Array.Copy(white_key, 0, keysCombined, 0, 16);
            Array.Copy(aes_key, 0, keysCombined, 16, 16);
            Array.Copy(hash_key, 0, keysCombined, 32, 16);
            WriteFile(keysOutputPath, keysCombined);
            Console.WriteLine($"Keys written to: {keysOutputPath}");

            WriteFile(Path.Combine(outputFolder, "HV.dec.bin"), hv_dec);
            WriteFile(Path.Combine(outputFolder, "HV.enc.bin"), hv_enc);
            WriteFile(Path.Combine(outputFolder, "sram.bin"), sram);

            Console.WriteLine("Cash files generated successfully.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error processing hypervisor: {ex.Message}");
            if (EnableDebug)
            {
                Console.WriteLine(ex.StackTrace);
            }
        }
    }

    //static void HandleCashCommand(string[] args)
    //{
    //    string inputFile = DefaultHvDecFilePath;
    //    string keysFile = DefaultKeyFilePath;
    //    string outputFolder = DefaultOutputFolder;

    //    for (int i = 1; i < args.Length; i++)
    //    {
    //        if (args[i] == "--input" && i + 1 < args.Length)
    //        {
    //            inputFile = args[i + 1];
    //            i++;
    //        }
    //        else if (args[i] == "--keys" && i + 1 < args.Length)
    //        {
    //            keysFile = args[i + 1];
    //            i++;
    //        }
    //        else if (args[i] == "--output" && i + 1 < args.Length)
    //        {
    //            outputFolder = args[i + 1];
    //            i++;
    //        }
    //    }

    //    if (!File.Exists(inputFile))
    //    {
    //        Console.WriteLine($"Error: Input file not found at {inputFile}");
    //        return;
    //    }

    //    // Ensure default keys exist
    //    EnsureDefaultKeys();

    //    byte[] hv_dec = ReadFile(inputFile);
    //    if (hv_dec.Length < 0x40000)
    //    {
    //        Console.WriteLine($"Error: Hypervisor file must be at least 0x40000 bytes. Current size: {hv_dec.Length}");
    //        return;
    //    }

    //    byte[] white_key = ALL_55_KEY;
    //    byte[] aes_key = ALL_55_KEY;
    //    byte[] hash_key = ALL_55_KEY;

    //    if (File.Exists(keysFile))
    //    {
    //        byte[] keys = ReadFile(keysFile);
    //        if (keys.Length >= 0x30)
    //        {
    //            white_key = keys.Take(0x10).ToArray();
    //            aes_key = keys.Skip(0x10).Take(0x10).ToArray();
    //            hash_key = keys.Skip(0x20).Take(0x10).ToArray();
    //        }
    //    }

    //    Console.WriteLine("Using keys:");
    //    Console.WriteLine("W: " + BitConverter.ToString(white_key).Replace("-", ""));
    //    Console.WriteLine("A: " + BitConverter.ToString(aes_key).Replace("-", ""));
    //    Console.WriteLine("H: " + BitConverter.ToString(hash_key).Replace("-", ""));
    //    Console.WriteLine();

    //    // Generate encrypted hypervisor
    //    byte[] hv_enc;
    //    using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
    //    {
    //        DebugLog("[DEBUG] Starting encryption for cash...");
    //        hv_enc = mem.Encrypt(hv_dec, 0, hv_dec.Length, 0, false);
    //    }

    //    // Calculate SRAM checksums
    //    byte[] sram;
    //    using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
    //    {
    //        DebugLog("[DEBUG] Calculating SRAM checksums for cash...");
    //        sram = mem.CalcSram(hv_dec);
    //    }

    //    // Calculate 100F0 hash at fixed address 0x100F0
    //    byte[] hash100F0;
    //    int fixed_addr = 0x100F0;
    //    using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
    //    {
    //        DebugLog("[DEBUG] Calculating 100F0 hash...");
    //        hash100F0 = mem.Calc100F0(hv_dec, fixed_addr);
    //    }

    //    // Inject the 100F0 hash into the hypervisor at 0x100F0
    //    byte[] hv_100f0_dec = hv_dec.ToArray();
    //    using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
    //    {
    //        hv_100f0_dec = mem.Inject100F0Hash(hv_100f0_dec, hash100F0, fixed_addr);
    //        Console.WriteLine("[DEBUG] 100F0 hash injected into hypervisor.");
    //    }

    //    // Encrypt the modified hypervisor
    //    byte[] hv_100f0_enc;
    //    using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
    //    {
    //        DebugLog("[DEBUG] Starting encryption for 100F0 hypervisor...");
    //        hv_100f0_enc = mem.Encrypt(hv_100f0_dec, 0, hv_100f0_dec.Length, 0, false);
    //    }

    //    // Create the output folder if it doesn't exist
    //    if (!Directory.Exists(outputFolder))
    //    {
    //        Directory.CreateDirectory(outputFolder);
    //        Console.WriteLine($"Created output folder: {outputFolder}");
    //    }

    //    // Write all files
    //    string keysOutputPath = Path.Combine(outputFolder, "keys.bin");
    //    byte[] keysCombined = new byte[48];
    //    Array.Copy(white_key, 0, keysCombined, 0x00, 0x10);
    //    Array.Copy(aes_key, 0, keysCombined, 0x10, 0x10);
    //    Array.Copy(hash_key, 0, keysCombined, 0x20, 0x10);
    //    WriteFile(keysOutputPath, keysCombined);
    //    Console.WriteLine($"Keys written to {keysOutputPath}");

    //    WriteFile(Path.Combine(outputFolder, "HV.dec.bin"), hv_dec);
    //    WriteFile(Path.Combine(outputFolder, "HV.enc.bin"), hv_enc);
    //    WriteFile(Path.Combine(outputFolder, "100F0_HV.dec.bin"), hv_100f0_dec);
    //    WriteFile(Path.Combine(outputFolder, "100F0_HV.enc.bin"), hv_100f0_enc);
    //    WriteFile(Path.Combine(outputFolder, "sram.bin"), sram);

    //    Console.WriteLine("Cash files generated successfully.");
    //}

    static void HandleGenerate100f0Command(string[] args)
    {
        string inputFile = DefaultHvDecFilePath;
        string keysFile = DefaultKeyFilePath;
        string outputFile = Path.Combine(DefaultOutputFolder, "100f0_hv");

        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--input" && i + 1 < args.Length)
            {
                inputFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--keys" && i + 1 < args.Length)
            {
                keysFile = args[i + 1];
                i++;
            }
            else if (args[i] == "--output" && i + 1 < args.Length)
            {
                outputFile = args[i + 1];
                i++;
            }
        }

        if (!File.Exists(inputFile))
        {
            Console.WriteLine($"Error: Input file not found at {inputFile}");
            return;
        }

        // Ensure default keys exist
        EnsureDefaultKeys();

        byte[] hv_dec = ReadFile(inputFile);
        if (hv_dec.Length < 0x40000)
        {
            Console.WriteLine($"Error: Hypervisor file must be at least 0x40000 bytes. Current size: {hv_dec.Length}");
            return;
        }

        byte[] white_key = ALL_55_KEY;
        byte[] aes_key = ALL_55_KEY;
        byte[] hash_key = ALL_55_KEY;

        if (File.Exists(keysFile))
        {
            byte[] keys = ReadFile(keysFile);
            if (keys.Length >= 0x30)
            {
                white_key = keys.Take(0x10).ToArray();
                aes_key = keys.Skip(0x10).Take(0x10).ToArray();
                hash_key = keys.Skip(0x20).Take(0x10).ToArray();
            }
        }

        int fixed_addr = 0x100F0;
        byte[] hash100F0;
        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            DebugLog("[DEBUG] Calculating 100F0 hash...");
            hash100F0 = mem.Calc100F0(hv_dec, fixed_addr);
        }

        byte[] hv_100f0_dec = hv_dec.ToArray();
        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            hv_100f0_dec = mem.Inject100F0Hash(hv_100f0_dec, hash100F0, fixed_addr);
        }

        byte[] hv_100f0_enc;
        using (var mem = new MemoryCrypto(white_key, aes_key, hash_key))
        {
            DebugLog("[DEBUG] Starting encryption for 100F0 hypervisor...");
            hv_100f0_enc = mem.Encrypt(hv_100f0_dec, 0, hv_100f0_dec.Length, 0, false);
        }

        WriteFile(outputFile + "_dec.bin", hv_100f0_dec);
        WriteFile(outputFile + "_enc.bin", hv_100f0_enc);
        Console.WriteLine($"100F0 hypervisor files generated at {outputFile}_dec.bin and {outputFile}_enc.bin");
    }

    static void Main(string[] args)
    {
        // Check for debug mode
        if (args.Contains("--debug"))
        {
            EnableDebug = true;
            Console.WriteLine("Debug mode enabled.");
        }

        // Ensure default directories exist
        EnsureDefaultDirectories();

        // Initialize GF2 table
        GF2_TAB = GenerateGf2Table(GF2_IV, GF2_POLY);

        if (args.Length == 0)
        {
            Console.WriteLine("Usage: HyperVault <command> [options]");
            Console.WriteLine("Commands:");
            Console.WriteLine("  calculate         Perform hash and key blob calculations");
            Console.WriteLine("  encrypt           Encrypt a decrypted hypervisor");
            Console.WriteLine("  decrypt           Decrypt an encrypted hypervisor");
            Console.WriteLine("  cash              Generate a folder with keys, hypervisor, SRAM checksums, and 100F0 hypervisor");
            Console.WriteLine("  generate100f0     Generate a 100F0 hypervisor");
            Console.WriteLine();
            Console.WriteLine("Options:");
            Console.WriteLine("  --debug           Enable debug logs");
            Console.WriteLine();
            Console.WriteLine("Default paths (if not specified):");
            Console.WriteLine($"  Keys:            {DefaultKeyFilePath}");
            Console.WriteLine($"  Decrypted HV:    {DefaultHvDecFilePath}");
            Console.WriteLine($"  Encrypted HV:    {DefaultHvEncFilePath}");
            Console.WriteLine($"  Output folder:   {DefaultOutputFolder}");
            return;
        }

        string command = args[0].ToLower();

        try
        {
            switch (command)
            {
                case "calculate":
                    HandleCalculateCommand(args);
                    break;
                case "decrypt":
                    HandleDecryptCommand(args);
                    break;
                case "encrypt":
                    HandleEncryptCommand(args);
                    break;
                case "cash":
                    HandleCashCommand(args);
                    break;
                case "generate100f0":
                    HandleGenerate100f0Command(args);
                    break;
                default:
                    Console.WriteLine($"Unknown command: {command}");
                    Console.WriteLine("Available commands: calculate, encrypt, decrypt, cash, generate100f0");
                    break;
            }

            Console.WriteLine("Done!");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            if (EnableDebug)
            {
                Console.WriteLine(ex.StackTrace);
            }
        }
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