package xenon360.xex;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;

/** Diagnostic XEX integrity verification. Verification never mutates source or image bytes. */
public final class XenonXexIntegrity {
    public record Result(String signature, String headerHash, String imageHash, String importHash) {
        public boolean allApplicableHashesValid() {
            return goodHash(headerHash) && goodHash(imageHash) && goodHash(importHash);
        }
        private static boolean goodHash(String s) {
            return s.equals("valid") || s.equals("not-present") || s.equals("not-supported");
        }
    }

    private record PublicKey(String name, byte[] bytes) { }
    private static final String RETAIL_KEY =
        "00000020000000030000000000000000e63b32b28d9e9ee79dfc5c7241945847" +
        "de0d184072d6e3468eba8ebc1a90ac20ba0385b51a3e25f9a658ebb6a3c4a3ee" +
        "b2b0ae9769ebfe71fc02ab77bac8e674e67c630eaf4cf7e7114a802472057a63" +
        "d0f89102a6e77d77c5a79b08112ea064456046bc36e11771be66492fae20a476" +
        "9c2751cf4b347a35bca4aa1c474bf497224e1324d3c157df4d84b9189799ac00" +
        "b33d032560c87a59fe48ff283d10bb9e09062a61202cf872eb87e6d1fbb366fc" +
        "4a02aed4d837cfa6322579360ef4ed19a21027962f9fa93da43730115183bdf7c" +
        "7e5ceaaecde48a084f7b0f64b8ef089bd477c90dd88121740d24ea6c611041b5" +
        "7a868b461f41bc68be8d920f205e070";
    private static final String DEVKIT_KEY =
        "00000020000000030000000000000000c91c3577c8bfa06b642f4e6c7399ace5" +
        "84e7ab2ee4dbae1e3e0670624aa2ad99e1767061e6be93276d5d97fd7330763a" +
        "b8705cc0be8f1b3d4c5d8565988c4c6bccbed0c5a743aa6c56910ff8e8bd904d" +
        "b8d9a3f13b6e71dbb0e0f51a8e8039c24e3a8142c56eb94944f48dc58451c81" +
        "b7dbc4559d0e3f297efa039ea1cf94866664e8bd022abdb901ebcd83d91a7897c" +
        "7207da63aaf33eedd587667bf2289cb34054226544102ad2b0484cf99e6fa4769" +
        "f18d04dada56efc9ec2a4cfb3ecc805ed8c08ed2513ccbb16601a8ac74b68937" +
        "f95271acc7bac29d4b7419b0a996002a6e9a7c278f5c0b8bb9d8816716481072" +
        "c5b33e51cfa0002d7492f13b1c17fbf";
    private static final String RETAIL_LIVE_KEY =
        "00000020000100010000000000000000f2e53e3f0375c2b320b6ab4190789da1" +
        "044e586dfcff161c9e011dda5d167e54cb2af2a70283e8adcda100f89cc4ad2d" +
        "4caf2e18019f38b13dfac9a6cf2aa84ee07e172361fbfd362e2217fa7571a074" +
        "f9f710857eec5c35f5b0acabc10b091d9a7abeb9b791780a5dcacbf9984b681" +
        "575771cb0ccfa04a3ec08dd685fea69af9d98b9bff372fcc01e5b155b49aa6ad" +
        "c5535393f8cdcc757a775214108bb9b746cfbf689c4b3ebd07eafa7a72725417" +
        "059ac9618160ee96b11c7ee355272a4c2b31e2005c5c09c5dc7cf5b81beb2b3" +
        "af8385de736e7a0eac590d4673fb7b788829875ae67b2e7d868255be1212d987" +
        "b3bd3d41c8d000f57dc97b518ec735dcef";
    private static final String DEVKIT_LIVE_KEY =
        "000000200000000300000000000000009212cd8727f129a5b3bad1dd2f59a83f" +
        "653062b2d1b42d7e2f5b2f7f6389a994c10a4616665443ac780738b2f9eb6418" +
        "c426c839613cece562dd9259426de93ecaae81041929f0046dc586ae484cf919f" +
        "b8a315432cc5288259e9842433cb26307ca71a3973ed38d4e44a956a3d2fd40b" +
        "81a5eee23927db4a8f704c702f9f3957782e25c309024ce7d05194fbe3999778" +
        "2ef917468b0555da74dfa7b9111f5a9dda13f872176b0b17dd69d90bddcd1565" +
        "ca7ee6f80da783363d2615b31baddb48efc762a97c5e8006e3c7aff18b3aafe7" +
        "8e898a8efa8636e9602f782cc49bcf77758d6844e5888c61f3f35d530a14ac0d" +
        "da0f6e6068e1c84b5ff62ebec7bc33d";
    private static final List<PublicKey> KEYS = List.of(
        key("retail", RETAIL_KEY), key("devkit", DEVKIT_KEY),
        key("retail-LIVE", RETAIL_LIVE_KEY), key("devkit-LIVE", DEVKIT_LIVE_KEY));

    private XenonXexIntegrity() { }

    public static Result verify(byte[] source, XexImage image) throws IOException {
        String magic = image.containerMagic;
        String signature = "not-supported";
        String header = "not-supported";
        String importHash = "not-supported";
        if (magic.equals("XEX2")) {
            signature = verifySignature(source);
            header = verifyHeaderHash(source);
            importHash = verifyImportHash(source);
        }
        String imageHash = magic.equals("XEX%") || magic.equals("XEX1") || magic.equals("XEX2")
            ? verifyImageHash(source, image) : "not-supported";
        return new Result(signature, header, imageHash, importHash);
    }

    private static PublicKey key(String name, String hex) {
        return new PublicKey(name, HexFormat.of().parseHex(hex));
    }

    private static String verifySignature(byte[] source) throws IOException {
        int security = checkedInt(be32(source, 16), "security offset");
        range(source, security + 8, 0x174, "XEX2 image info");
        byte[] info = Arrays.copyOfRange(source, security + 8, security + 8 + 0x174);
        byte[] hash = rotSumSha(Arrays.copyOfRange(info, 0x100, info.length));
        long flags = be32(info, 0x104);
        byte[] salt = (flags & 0x80000000L) != 0
            ? "XBOX360REV".getBytes(java.nio.charset.StandardCharsets.US_ASCII)
            : "XBOX360XEX".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] signature = Arrays.copyOfRange(info, 0, 0x100);
        for (PublicKey key : KEYS)
            if (verifyXboxSignature(signature, hash, salt, key.bytes))
                return "valid:" + key.name;
        return "unknown-key-or-invalid";
    }

    private static String verifyHeaderHash(byte[] source) throws IOException {
        int headerSize = checkedInt(be32(source, 8), "header size");
        int security = checkedInt(be32(source, 16), "security offset");
        int infoEnd = security + 8 + 0x174;
        range(source, 0, headerSize, "XEX2 headers");
        if (infoEnd > headerSize) throw bad("XEX2 image info exceeds headers");
        byte[] actual = sha1(Arrays.copyOfRange(source, infoEnd, headerSize),
            Arrays.copyOfRange(source, 0, security + 8));
        byte[] expected = Arrays.copyOfRange(source, security + 0x164, security + 0x178);
        return MessageDigest.isEqual(actual, expected) ? "valid" : "invalid";
    }

    private static String verifyImageHash(byte[] source, XexImage x) throws IOException {
        int security = checkedInt(be32(source, 16), "security offset");
        boolean xex25 = x.containerMagic.equals("XEX%");
        boolean xex1 = x.containerMagic.equals("XEX1");
        int countOffset = xex25 ? 0x150 : xex1 ? 0x164 : 0x180;
        int tableOffset = xex25 ? 0x154 : xex1 ? 0x168 : 0x184;
        int flagsOffset = xex25 ? 0x144 : xex1 ? 0x158 : 0x10c;
        int hashOffset = xex25 || xex1 ? 0x11c : 0x114;
        int count = checkedInt(be32(source, security + countOffset), "page descriptor count");
        if (count == 0) return "not-present";
        long flags = be32(source, security + flagsOffset);
        int pageSize = (flags & 0x10000000L) != 0 ? 4096 : 65536;
        byte[] expected = Arrays.copyOfRange(source, security + hashOffset, security + hashOffset + 20);
        int dataOffset = 0;
        for (int i = 0; i < count; i++) {
            int p = security + tableOffset + i * 24;
            range(source, p, 24, "page descriptor");
            int bytes = checkedInt((be32(source, p) >>> 4) * pageSize, "page span");
            range(x.image, dataOffset, bytes, "reconstructed page");
            byte[] actual = sha1(Arrays.copyOfRange(x.image, dataOffset, dataOffset + bytes),
                Arrays.copyOfRange(source, p, p + 24));
            if (!MessageDigest.isEqual(actual, expected)) return "invalid";
            expected = Arrays.copyOfRange(source, p + 4, p + 24);
            dataOffset += bytes;
        }
        return dataOffset == x.image.length ? "valid" : "invalid";
    }

    private static String verifyImportHash(byte[] source) throws IOException {
        int security = checkedInt(be32(source, 16), "security offset");
        int importCount = checkedInt(be32(source, security + 0x128), "import table count");
        if (importCount == 0) return "not-present";
        int count = checkedInt(be32(source, 20), "optional header count");
        int importOffset = -1;
        for (int i = 0; i < count; i++) {
            long key = be32(source, 24 + i * 8);
            if (key == 0x000103ffL) importOffset = checkedInt(be32(source, 28 + i * 8), "imports offset");
        }
        if (importOffset < 0) return "invalid";
        int span = checkedInt(be32(source, importOffset), "imports size");
        range(source, importOffset, span, "imports span");
        int strings = checkedInt(be32(source, importOffset + 4), "import strings size");
        int modules = checkedInt(be32(source, importOffset + 8), "import module count");
        if (modules != importCount) return "invalid";
        int p = importOffset + 12 + strings;
        int end = importOffset + span;
        byte[] expected = Arrays.copyOfRange(source, security + 0x12c, security + 0x140);
        for (int i = 0; i < modules; i++) {
            if (p + 4 > end) return "invalid";
            int size = checkedInt(be32(source, p), "import table size");
            if (size < 24 || p + size > end) return "invalid";
            byte[] table = Arrays.copyOfRange(source, p + 4, p + size);
            if (!MessageDigest.isEqual(sha1(table), expected)) return "invalid";
            expected = Arrays.copyOfRange(table, 0, 20);
            p += size;
        }
        return "valid";
    }

    private static boolean verifyXboxSignature(byte[] signature, byte[] hash, byte[] salt, byte[] key) {
        try {
            int cqw = (int)be32(key, 0), exponent = (int)be32(key, 4);
            if (cqw != 32 || key.length < 16 + cqw * 8) return false;
            BigInteger modulus = xeInteger(Arrays.copyOfRange(key, 16, 16 + cqw * 8));
            BigInteger sig = xeInteger(signature);
            long rExponent = ((long)exponent - 1L) << 11;
            BigInteger r = BigInteger.TWO.modPow(BigInteger.valueOf(rExponent), modulus);
            BigInteger decoded = sig.modPow(BigInteger.valueOf(Integer.toUnsignedLong(exponent)), modulus)
                .multiply(r.modInverse(modulus)).mod(modulus);
            byte[] sb = swapWithinQwords(toLittleEndian(decoded, cqw * 8));
            byte[] block = reverseQwords(sb);
            if ((block[0xff] & 255) != 0xbc) return false;
            byte[] abHash = sha1(new byte[8], hash, salt);
            if (!MessageDigest.isEqual(abHash, Arrays.copyOfRange(block, 0xeb, 0xff))) return false;
            byte[] plain = rc4(abHash, Arrays.copyOfRange(block, 0, 0xeb));
            if ((plain[0xe0] & 255) != 1) return false;
            for (int i = 1; i < 0xe0; i++) if (plain[i] != 0) return false;
            for (int i = 0; i < salt.length; i++) if (plain[0xe1 + i] != salt[i]) return false;
            return true;
        }
        catch (Exception ex) { return false; }
    }

    private static byte[] rotSumSha(byte[] data) {
        long a = 0, b = 0, c = 0, d = 0;
        for (int p = 0; p + 8 <= data.length; p += 8) {
            long x = ByteBuffer.wrap(data, p, 8).order(ByteOrder.BIG_ENDIAN).getLong();
            b += x; d -= x;
            if (Long.compareUnsigned(b, x) < 0) a++;
            b = Long.rotateLeft(b, 29);
            if (Long.compareUnsigned(x, d) < 0) c--;
            d = Long.rotateLeft(d, 31);
        }
        ByteBuffer bb = ByteBuffer.allocate(32).order(ByteOrder.BIG_ENDIAN);
        bb.putLong(a).putLong(b).putLong(c).putLong(d);
        byte[] rot = bb.array(), inv = rot.clone();
        for (int i = 0; i < inv.length; i++) inv[i] = (byte)~inv[i];
        return sha1(rot, rot, data, inv, inv);
    }

    private static BigInteger xeInteger(byte[] bytes) {
        byte[] swapped = swapWithinQwords(bytes);
        reverse(swapped);
        return new BigInteger(1, swapped);
    }

    private static byte[] toLittleEndian(BigInteger value, int size) {
        byte[] raw = value.toByteArray();
        if (raw.length > 1 && raw[0] == 0) raw = Arrays.copyOfRange(raw, 1, raw.length);
        byte[] be = new byte[size];
        System.arraycopy(raw, 0, be, size - raw.length, raw.length);
        reverse(be);
        return be;
    }

    private static byte[] swapWithinQwords(byte[] bytes) {
        byte[] out = bytes.clone();
        for (int p = 0; p < out.length; p += 8)
            for (int i = 0; i < 4; i++) {
                byte t = out[p + i]; out[p + i] = out[p + 7 - i]; out[p + 7 - i] = t;
            }
        return out;
    }

    private static byte[] reverseQwords(byte[] bytes) {
        byte[] out = new byte[bytes.length];
        int count = bytes.length / 8;
        for (int i = 0; i < count; i++)
            System.arraycopy(bytes, i * 8, out, (count - 1 - i) * 8, 8);
        return out;
    }

    private static void reverse(byte[] bytes) {
        for (int i = 0, j = bytes.length - 1; i < j; i++, j--) {
            byte t = bytes[i]; bytes[i] = bytes[j]; bytes[j] = t;
        }
    }

    private static byte[] rc4(byte[] key, byte[] data) {
        int[] s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + (key[i % key.length] & 255)) & 255;
            int t = s[i]; s[i] = s[j]; s[j] = t;
        }
        byte[] out = new byte[data.length];
        int i = 0; j = 0;
        for (int p = 0; p < data.length; p++) {
            i = (i + 1) & 255; j = (j + s[i]) & 255;
            int t = s[i]; s[i] = s[j]; s[j] = t;
            out[p] = (byte)(data[p] ^ s[(s[i] + s[j]) & 255]);
        }
        return out;
    }

    private static byte[] sha1(byte[]... parts) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            for (byte[] part : parts) md.update(part);
            return md.digest();
        }
        catch (GeneralSecurityException ex) { throw new IllegalStateException(ex); }
    }

    private static long be32(byte[] b, int p) throws IOException {
        range(b, p, 4, "BE32");
        return ((long)(b[p] & 255) << 24) | ((long)(b[p + 1] & 255) << 16)
            | ((long)(b[p + 2] & 255) << 8) | (b[p + 3] & 255L);
    }

    private static int checkedInt(long v, String what) throws IOException {
        if (v < 0 || v > Integer.MAX_VALUE) throw bad(what + " exceeds Java bounds");
        return (int)v;
    }

    private static void range(byte[] b, int p, int n, String what) throws IOException {
        if (p < 0 || n < 0 || p > b.length || n > b.length - p)
            throw bad(what + " outside bounds");
    }

    private static IOException bad(String s) { return new IOException(s); }
}
