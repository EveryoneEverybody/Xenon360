package xenon360.xex;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Synthetic end-to-end XEXP application tests. */
public final class XexPatchSelfTest {
    private static final int HEADER = 0x1000;
    private static final int SECURITY = 0x100;
    private static final int FORMAT = 0x300;
    private static final int DELTA = 0x340;
    private static final byte[] SESSION =
        HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
    private static int checks;

    private static void check(boolean condition, String name) {
        if (!condition) throw new AssertionError(name);
        checks++;
        System.out.println("PASS " + name);
    }

    private static void be32(byte[] a, int p, long n) {
        ByteBuffer.wrap(a).order(ByteOrder.BIG_ENDIAN).putInt(p, (int)n);
    }

    private static void be16(byte[] a, int p, int n) {
        ByteBuffer.wrap(a).order(ByteOrder.BIG_ENDIAN).putShort(p, (short)n);
    }

    private static byte[] encrypt(byte[] key, byte[] data) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
            new IvParameterSpec(new byte[16]));
        return c.doFinal(data);
    }

    private static byte[] sha1(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(data);
    }

    private static byte[] syntheticPatch(byte[] base) throws Exception {
        byte[] body = new byte[24 + 12 + 12 + 12];
        int p = 24;

        // Copy a known import marker word to unused .data bytes.
        be32(body, p, 0x3000); be32(body, p + 4, 0x3020);
        be16(body, p + 8, 4); be16(body, p + 10, 1);
        p += 12;

        // Zero the second import marker word.
        be32(body, p, 0x3004); be32(body, p + 4, 0x3004);
        be16(body, p + 8, 4); be16(body, p + 10, 0);
        p += 12;

        // All-zero record terminates this block.
        byte[] bodyHash = sha1(body);

        byte[] patch = new byte[HEADER + body.length];
        patch[0] = 'X'; patch[1] = 'E'; patch[2] = 'X'; patch[3] = '2';
        be32(patch, 4, 0x50);
        be32(patch, 8, HEADER);
        be32(patch, 16, SECURITY);
        be32(patch, 20, 2);
        be32(patch, 24, 0x000003ff); be32(patch, 28, FORMAT);
        be32(patch, 32, 0x000005ff); be32(patch, 36, DELTA);

        be32(patch, SECURITY, 0x184);
        be32(patch, SECURITY + 4, XexImageSelfTest.image().length);

        be32(patch, FORMAT, 36);
        be16(patch, FORMAT + 4, 0);
        be16(patch, FORMAT + 6, 3);
        be32(patch, FORMAT + 8, 0x8000);
        be32(patch, FORMAT + 12, body.length);
        System.arraycopy(bodyHash, 0, patch, FORMAT + 16, bodyHash.length);

        be32(patch, DELTA, 0x58);
        be32(patch, DELTA + 4, 0x20168600L);
        be32(patch, DELTA + 8, 0x20076000L);

        int baseSecurity = ByteBuffer.wrap(base).order(ByteOrder.BIG_ENDIAN).getInt(16);
        byte[] signature = Arrays.copyOfRange(base, baseSecurity + 8, baseSecurity + 0x108);
        System.arraycopy(sha1(signature), 0, patch, DELTA + 0x0c, 20);

        // Header patch is a no-op COPY of the fixed header_size word.
        be32(patch, DELTA + 0x30, HEADER);
        be32(patch, DELTA + 0x34, 0);
        be32(patch, DELTA + 0x38, 0);
        be32(patch, DELTA + 0x3c, 0);
        be32(patch, DELTA + 0x40, 0);
        be32(patch, DELTA + 0x44, XexImageSelfTest.image().length);
        be32(patch, DELTA + 0x48, 0);
        be32(patch, DELTA + 0x4c, 8);
        be32(patch, DELTA + 0x50, 8);
        be16(patch, DELTA + 0x54, 4);
        be16(patch, DELTA + 0x56, 1);

        // The patched base header keeps the same session key, so encrypt the
        // old session key under that same new session key for image_key_source.
        byte[] keySource = encrypt(SESSION, SESSION);
        System.arraycopy(keySource, 0, patch, DELTA + 0x20, 16);

        System.arraycopy(body, 0, patch, HEADER, body.length);
        return patch;
    }

    public static void main(String[] args) throws Exception {
        byte[] base = XexImageSelfTest.fixture(1, "retail");
        byte[] patch = syntheticPatch(base);

        XexPatch.Metadata metadata = XexPatch.inspect(patch);
        check(metadata.compression() == 3 && metadata.encryption() == 0,
            "synthetic DELTA metadata");
        check(metadata.headerPatch().kind() == XexPatch.RecordKind.COPY,
            "synthetic header copy record");

        XexPatch.PayloadInfo payload = XexPatch.inspectUnencryptedPayload(patch, true);
        check(payload.blockCount() == 1 && payload.recordCount() == 2,
            "synthetic payload record count");
        check(payload.copyRecords() == 1 && payload.zeroRecords() == 1
            && payload.lzxDeltaRecords() == 0, "synthetic payload record kinds");

        XexPatch.Applied applied = XexPatch.apply(base, patch);
        check(applied.keyKind().equals("retail"), "synthetic patch retail key path");
        check(applied.targetCompression() == 1 && applied.targetEncryption() == 1,
            "synthetic target header state before normalization");
        check(applied.image().compression == 0 && applied.image().encryption == 0,
            "synthetic patched image normalized");

        byte[] expected = XexImageSelfTest.image();
        System.arraycopy(expected, 0x3000, expected, 0x3020, 4);
        Arrays.fill(expected, 0x3004, 0x3008, (byte)0);
        check(Arrays.equals(applied.image().image, expected),
            "synthetic end-to-end patched image equality");
        check(Arrays.equals(XexImage.parse(applied.normalizedXex()).image, expected),
            "synthetic normalized XEX reparses identically");

        byte[] wrongBase = base.clone();
        wrongBase[SECURITY + 8] ^= 1;
        try {
            XexPatch.apply(wrongBase, patch);
            throw new AssertionError("Accepted wrong base signature");
        }
        catch (IOException ex) {
            check(ex.getMessage().contains("source signature digest"),
                "reject wrong XEXP base signature");
        }

        System.out.println("XEXP_SELF_TEST_PASS checks=" + checks);
    }
}
