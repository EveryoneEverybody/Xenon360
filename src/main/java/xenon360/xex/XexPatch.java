package xenon360.xex;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** XEX2 XEXP/DELTA parser and in-memory patch applicator. */
public final class XexPatch {
    private static final long FORMAT = 0x000003ffL;
    private static final long DELTA = 0x000005ffL;
    private static final int MODULE_PATCH = 0x10;
    private static final int PATCH_DELTA = 0x40;
    private static final byte[] RETAIL =
        HexFormat.of().parseHex("20b185a59d28fdc340583fbb0896bf91");

    public enum RecordKind { ZERO, COPY, LZX_DELTA }

    public record DeltaRecord(long oldAddress, long newAddress, int uncompressedLength,
                              int compressedLength, byte[] patchData, RecordKind kind) { }

    public record Metadata(String sourceSha256, int moduleFlags, int headerSize,
                           int encryption, int compression, int windowSize,
                           long sourceVersion, long targetVersion, byte[] sourceSignatureSha1,
                           byte[] imageKeySource, int sizeOfTargetHeaders,
                           long deltaHeadersSourceOffset, long deltaHeadersSourceSize,
                           long deltaHeadersTargetOffset, long deltaImageSourceOffset,
                           long deltaImageSourceSize, long deltaImageTargetOffset,
                           DeltaRecord headerPatch, int firstBlockSize, byte[] firstBlockHash) {
        public String sourceVersionHex() { return String.format("0x%08X", sourceVersion); }
        public String targetVersionHex() { return String.format("0x%08X", targetVersion); }
    }

    public record PayloadInfo(int blockCount, int recordCount, int zeroRecords,
                              int copyRecords, int lzxDeltaRecords, int paddingBytes,
                              List<DeltaRecord> records) { }

    public record Applied(XexImage image, byte[] normalizedXex, Metadata patch,
                          String keyKind, PayloadInfo payloadInfo,
                          int targetEncryption, int targetCompression) { }

    private record Span(long offset, long size, long value, boolean inline) { }
    private record Container(byte[] bytes, int moduleFlags, int headerSize, int securityOffset,
                             int imageSize, int encryption, int compression, int windowSize,
                             int firstBlockSize, byte[] firstBlockHash, byte[] fileKey,
                             byte[] rsaSignature, Map<Long, Span> optional) { }

    private XexPatch() { }

    public static boolean isDeltaPatch(byte[] bytes) {
        if (bytes.length < 8 || bytes[0] != 'X' || bytes[1] != 'E'
                || bytes[2] != 'X' || bytes[3] != '2') return false;
        long flags = (long)(bytes[4] & 255) << 24 | (long)(bytes[5] & 255) << 16
            | (long)(bytes[6] & 255) << 8 | (bytes[7] & 255);
        return (flags & (MODULE_PATCH | PATCH_DELTA)) == (MODULE_PATCH | PATCH_DELTA);
    }

    public static Metadata inspect(byte[] patchFile) throws IOException {
        if (patchFile.length > XexImage.MAX_FILE_BYTES)
            throw bad("XEXP file exceeds 256 MiB limit");
        Container c = container(patchFile);
        if ((c.moduleFlags & MODULE_PATCH) == 0 || (c.moduleFlags & PATCH_DELTA) == 0)
            throw bad("Expected XEX2 delta patch module flags");
        if (c.compression != 3) throw bad("Expected XEXP compression type DELTA (3)");
        Span d = c.optional.get(DELTA);
        if (d == null || d.inline || d.size < 0x58) throw bad("Missing/short XEXP delta descriptor");
        Reader r = new Reader(patchFile);
        long p = d.offset;
        int declared = checkedInt(r.be32(p), "delta descriptor size");
        if (declared < 0x58 || declared > d.size) throw bad("Invalid XEXP delta descriptor size");
        DeltaRecord headerRecord = deltaRecord(r, p + 0x4c, p + declared);
        return new Metadata(
            XexImage.sha256(patchFile), c.moduleFlags, c.headerSize, c.encryption, c.compression,
            c.windowSize, r.be32(p + 8), r.be32(p + 4),
            r.bytes(p + 0x0c, 20), r.bytes(p + 0x20, 16),
            checkedInt(r.be32(p + 0x30), "target header size"),
            r.be32(p + 0x34), r.be32(p + 0x38), r.be32(p + 0x3c),
            r.be32(p + 0x40), r.be32(p + 0x44), r.be32(p + 0x48),
            headerRecord, c.firstBlockSize, c.firstBlockHash);
    }

    public static PayloadInfo inspectUnencryptedPayload(byte[] patchFile, boolean decodeLzx)
            throws IOException {
        Metadata metadata = inspect(patchFile);
        if (metadata.encryption != 0)
            throw bad("Encrypted XEXP payload requires its matching base XEX");
        Container c = container(patchFile);
        byte[] plain = Arrays.copyOfRange(patchFile, c.headerSize, patchFile.length);
        return parsePayload(plain, metadata, decodeLzx);
    }

    public static void verifyHeaderDeltaAgainstZeros(byte[] patchFile) throws IOException {
        Metadata m = inspect(patchFile);
        DeltaRecord record = m.headerPatch;
        if (record.kind == RecordKind.LZX_DELTA) {
            byte[] reference = new byte[record.uncompressedLength];
            new XenonLzxDecoder(m.windowSize).decompress(
                record.patchData, record.uncompressedLength, reference);
        }
    }

    public static Applied apply(byte[] baseFile, byte[] patchFile) throws IOException {
        Metadata patch = inspect(patchFile);
        Container base = container(baseFile);
        if ((base.moduleFlags & MODULE_PATCH) != 0) throw bad("Base XEX is itself a patch module");
        XexImage baseImage = XexImage.parse(baseFile);
        byte[] sourceDigest = digest("SHA-1", base.rsaSignature);
        if (!MessageDigest.isEqual(sourceDigest, patch.sourceSignatureSha1))
            throw bad("XEXP source signature digest does not match base XEX");

        List<String> keyKinds;
        if (baseImage.keyKind.equals("retail") || baseImage.keyKind.equals("devkit"))
            keyKinds = List.of(baseImage.keyKind);
        else
            keyKinds = List.of("retail", "devkit");

        List<String> failures = new ArrayList<>();
        for (String keyKind : keyKinds) {
            try {
                return applyWithKey(baseFile, base, baseImage, patchFile, patch, keyKind);
            }
            catch (IOException ex) {
                failures.add(keyKind + ": " + ex.getMessage());
            }
        }
        throw bad("XEXP application rejected; " + String.join("; ", failures));
    }

    private static Applied applyWithKey(byte[] baseFile, Container base, XexImage baseImage,
            byte[] patchFile, Metadata patch, String keyKind) throws IOException {
        byte[] master = keyKind.equals("retail") ? RETAIL : new byte[16];
        byte[] oldSession = decrypt(master, base.fileKey);

        int targetHeaderSize = patch.sizeOfTargetHeaders;
        if (targetHeaderSize == 0)
            targetHeaderSize = checkedInt(patch.deltaHeadersTargetOffset
                + patch.deltaHeadersSourceSize, "derived target header size");
        if (targetHeaderSize < 24 || targetHeaderSize > XexImage.MAX_FILE_BYTES)
            throw bad("XEXP target header size outside bounds");

        range(patch.deltaHeadersSourceOffset, patch.deltaHeadersSourceSize,
            base.headerSize, "XEXP header source range");
        range(patch.deltaHeadersTargetOffset, patch.deltaHeadersSourceSize,
            targetHeaderSize, "XEXP header target range");
        byte[] targetHeader = Arrays.copyOf(baseFile, targetHeaderSize);
        copyRangeSnapshot(targetHeader, patch.deltaHeadersSourceOffset,
            patch.deltaHeadersTargetOffset, patch.deltaHeadersSourceSize,
            base.headerSize, targetHeaderSize, "XEXP header source copy");
        applyRecord(targetHeader, patch.headerPatch, patch.windowSize);

        Container target = containerHeader(targetHeader, targetHeaderSize);
        if (target.headerSize != targetHeaderSize)
            throw bad("Patched XEX header size differs from delta target header size");

        byte[] newSession = decrypt(master, target.fileKey);
        Container patchContainer = container(patchFile);
        byte[] patchSession = decrypt(newSession, patchContainer.fileKey);
        byte[] recoveredOld = decrypt(newSession, patch.imageKeySource);
        if (!MessageDigest.isEqual(recoveredOld, oldSession))
            throw bad("XEXP image-key source does not match original base session key");

        byte[] encryptedPayload = Arrays.copyOfRange(
            patchFile, patchContainer.headerSize, patchFile.length);
        byte[] plainPayload;
        if (patch.encryption == 0) {
            plainPayload = encryptedPayload;
        }
        else {
            if ((encryptedPayload.length & 15) != 0)
                throw bad("Encrypted XEXP payload length is not a multiple of 16");
            plainPayload = decrypt(patchSession, encryptedPayload);
        }

        int workingSize = Math.max(baseImage.image.length, target.imageSize);
        byte[] image = Arrays.copyOf(baseImage.image, workingSize);
        range(patch.deltaImageSourceOffset, patch.deltaImageSourceSize,
            baseImage.image.length, "XEXP image source range");
        range(patch.deltaImageTargetOffset, patch.deltaImageSourceSize,
            workingSize, "XEXP image target range");
        copyRangeSnapshot(image, patch.deltaImageSourceOffset, patch.deltaImageTargetOffset,
            patch.deltaImageSourceSize, baseImage.image.length, workingSize,
            "XEXP image source copy");
        long retainedEnd = patch.deltaImageTargetOffset + patch.deltaImageSourceSize;
        if (retainedEnd < patch.deltaImageTargetOffset || retainedEnd > workingSize)
            throw bad("XEXP retained image prefix outside reconstructed image");
        if (retainedEnd < baseImage.image.length)
            Arrays.fill(image, checkedInt(retainedEnd, "retained image prefix"),
                baseImage.image.length, (byte)0);

        PayloadInfo payloadInfo = parseAndApplyPayload(plainPayload, patch, image);
        if (target.imageSize < 64 || target.imageSize > image.length)
            throw bad("Patched XEX image size outside reconstructed image");
        byte[] finalImage = Arrays.copyOf(image, target.imageSize);

        Span format = target.optional.get(FORMAT);
        if (format == null || format.inline || format.size < 8)
            throw bad("Patched XEX has no usable file-format header");
        byte[] normalizedHeader = targetHeader.clone();
        putBe16(normalizedHeader, checkedInt(format.offset + 4, "format encryption offset"), 0);
        putBe16(normalizedHeader, checkedInt(format.offset + 6, "format compression offset"), 0);

        byte[] normalized = new byte[targetHeaderSize + finalImage.length];
        System.arraycopy(normalizedHeader, 0, normalized, 0, targetHeaderSize);
        System.arraycopy(finalImage, 0, normalized, targetHeaderSize, finalImage.length);
        XexImage result = XexImage.parse(normalized);
        if (!Arrays.equals(result.image, finalImage))
            throw bad("Normalized patched XEX changed reconstructed image bytes");
        return new Applied(result, normalized, patch, keyKind, payloadInfo,
            target.encryption, target.compression);
    }

    private static PayloadInfo parsePayload(byte[] plain, Metadata patch, boolean decodeLzx)
            throws IOException {
        return walkPayload(plain, patch, null, decodeLzx);
    }

    private static PayloadInfo parseAndApplyPayload(byte[] plain, Metadata patch, byte[] image)
            throws IOException {
        return walkPayload(plain, patch, image, true);
    }

    private static PayloadInfo walkPayload(byte[] plain, Metadata patch, byte[] image,
            boolean decodeLzx) throws IOException {
        Reader r = new Reader(plain);
        int offset = 0, blockSize = patch.firstBlockSize, blocks = 0, padding = 0;
        byte[] expectedHash = patch.firstBlockHash;
        List<DeltaRecord> records = new ArrayList<>();
        int zero = 0, copy = 0, lzx = 0;

        while (blockSize != 0) {
            if (++blocks > 1048576) throw bad("Excessive XEXP block count");
            r.range(offset, blockSize, "XEXP block");
            if (blockSize < 24) throw bad("XEXP block shorter than chain header");
            byte[] actual = digest("SHA-1", Arrays.copyOfRange(plain, offset, offset + blockSize));
            if (!MessageDigest.isEqual(expectedHash, actual))
                throw bad("XEXP block SHA-1 mismatch at payload offset " + hex(offset));

            int nextSize = checkedInt(r.be32(offset), "next XEXP block size");
            byte[] nextHash = r.bytes(offset + 4L, 20);
            int p = offset + 24, end = offset + blockSize;
            boolean terminated = false;
            while (p < end) {
                if (end - p < 12) {
                    if (!allZero(plain, p, end)) throw bad("Nonzero truncated XEXP record tail");
                    padding += end - p; p = end; break;
                }
                DeltaRecord record = deltaRecord(r, p, end);
                if (record.oldAddress == 0 && record.newAddress == 0
                        && record.uncompressedLength == 0 && record.compressedLength == 0) {
                    p += 12;
                    if (!allZero(plain, p, end))
                        throw bad("Nonzero bytes after XEXP block terminator");
                    padding += end - p; p = end; terminated = true; break;
                }
                records.add(record);
                switch (record.kind) {
                    case ZERO -> zero++;
                    case COPY -> copy++;
                    case LZX_DELTA -> lzx++;
                }
                if (image != null) applyRecord(image, record, patch.windowSize);
                else if (decodeLzx && record.kind == RecordKind.LZX_DELTA) {
                    byte[] reference = new byte[record.uncompressedLength];
                    new XenonLzxDecoder(patch.windowSize).decompress(
                        record.patchData, record.uncompressedLength, reference);
                }
                p += recordBytes(record);
            }
            if (!terminated && p == end) {
                // Some producer blocks end exactly after the final record.
            }
            offset += blockSize;
            if (nextSize != 0 && (nextSize < 24 || nextSize > plain.length - offset))
                throw bad("Invalid chained XEXP block size " + hex(nextSize));
            blockSize = nextSize;
            expectedHash = nextHash;
        }
        if (offset > plain.length) throw bad("XEXP block chain exceeds payload");
        padding += plain.length - offset;
        if (!allZero(plain, offset, plain.length))
            throw bad("Nonzero trailing bytes after XEXP block chain");
        return new PayloadInfo(blocks, records.size(), zero, copy, lzx, padding,
            List.copyOf(records));
    }

    private static void applyRecord(byte[] destination, DeltaRecord record, int windowSize)
            throws IOException {
        int old = checkedInt(record.oldAddress, "delta old address");
        int target = checkedInt(record.newAddress, "delta new address");
        int length = record.uncompressedLength;
        range(target, length, destination.length, "XEXP delta target range");
        switch (record.kind) {
            case ZERO -> Arrays.fill(destination, target, target + length, (byte)0);
            case COPY -> {
                range(old, length, destination.length, "XEXP delta old range");
                byte[] source = Arrays.copyOfRange(destination, old, old + length);
                System.arraycopy(source, 0, destination, target, length);
            }
            case LZX_DELTA -> {
                range(old, length, destination.length, "XEXP delta old range");
                byte[] source = Arrays.copyOfRange(destination, old, old + length);
                byte[] decoded = new XenonLzxDecoder(windowSize).decompress(
                    record.patchData, length, source);
                System.arraycopy(decoded, 0, destination, target, length);
            }
        }
    }

    private static DeltaRecord deltaRecord(Reader r, long p, long end) throws IOException {
        range(p, 12, end, "XEXP delta record");
        long old = r.be32(p), target = r.be32(p + 4);
        int uncompressed = r.be16(p + 8), compressed = r.be16(p + 10);
        int dataLength = compressed <= 1 ? 0 : compressed;
        range(p + 12, dataLength, end, "XEXP delta record data");
        byte[] data = dataLength == 0 ? new byte[0] : r.bytes(p + 12, dataLength);
        RecordKind kind = compressed == 0 ? RecordKind.ZERO
            : compressed == 1 ? RecordKind.COPY : RecordKind.LZX_DELTA;
        return new DeltaRecord(old, target, uncompressed, compressed, data, kind);
    }

    private static int recordBytes(DeltaRecord record) {
        return 12 + (record.compressedLength <= 1 ? 0 : record.compressedLength);
    }

    private static Container container(byte[] file) throws IOException {
        return containerHeader(file, file.length);
    }

    private static Container containerHeader(byte[] bytes, int limit) throws IOException {
        Reader r = new Reader(bytes);
        r.range(0, 24, "XEX fixed header");
        if (r.u8(0) != 'X' || r.u8(1) != 'E' || r.u8(2) != 'X' || r.u8(3) != '2')
            throw bad("Expected XEX2 signature");
        int flags = checkedInt(r.be32(4), "module flags");
        int headerSize = checkedInt(r.be32(8), "XEX header size");
        int security = checkedInt(r.be32(16), "XEX security offset");
        int count = checkedInt(r.be32(20), "optional header count");
        if (headerSize < 24 || headerSize > limit) throw bad("XEX header size outside bounds");
        if (count > 4096) throw bad("Optional header count exceeds 4096");
        range(24, (long)count * 8, headerSize, "optional header table");

        Map<Long, Span> optional = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            long key = r.be32(24L + i * 8L), value = r.be32(28L + i * 8L);
            int tag = (int)(key & 255);
            boolean inline = tag <= 1;
            long size = inline ? 4 : tag == 255 ? r.be32(value) : tag * 4L;
            if (!inline) {
                if (size < 4) throw bad("Optional header is shorter than one word");
                range(value, size, headerSize, "optional header " + hex(key));
            }
            if (optional.put(key, new Span(value, size, value, inline)) != null)
                throw bad("Duplicate optional header " + hex(key));
        }

        range(security, 0x184, headerSize, "XEX security header");
        int securitySize = checkedInt(r.be32(security), "security header size");
        int imageSize = checkedInt(r.be32(security + 4L), "security image size");
        if (imageSize < 64 || imageSize > XexImage.MAX_IMAGE_BYTES)
            throw bad("security image size exceeds 512 MiB limit or is too small");
        range(security, securitySize, headerSize, "security header span");
        byte[] rsa = r.bytes(security + 8L, 0x100);
        byte[] fileKey = r.bytes(security + 0x150L, 16);

        Span format = optional.get(FORMAT);
        if (format == null || format.inline || format.size < 8)
            throw bad("Missing/short file-format header");
        int encryption = r.be16(format.offset + 4), compression = r.be16(format.offset + 6);
        if (encryption > 1) throw bad("Unsupported encryption type " + encryption);
        int window = 0, firstBlock = 0;
        byte[] firstHash = new byte[20];
        if (compression == 2 || compression == 3) {
            if (format.size < 36) throw bad("Short NORMAL/DELTA file-format header");
            window = checkedInt(r.be32(format.offset + 8), "LZX window size");
            if (window < (1 << 15) || window > (1 << 21) || (window & (window - 1)) != 0)
                throw bad("Invalid LZX window size " + hex(window));
            firstBlock = checkedInt(r.be32(format.offset + 12), "first block size");
            firstHash = r.bytes(format.offset + 16, 20);
        }
        return new Container(bytes, flags, headerSize, security, imageSize, encryption,
            compression, window, firstBlock, firstHash, fileKey, rsa, optional);
    }

    private static void copyRangeSnapshot(byte[] bytes, long source, long target, long size,
            int sourceLimit, int targetLimit, String what) throws IOException {
        if (source == 0 || size == 0) return;
        range(source, size, sourceLimit, what + " source");
        range(target, size, targetLimit, what + " target");
        int s = checkedInt(source, what + " source offset");
        int t = checkedInt(target, what + " target offset");
        int n = checkedInt(size, what + " size");
        byte[] snapshot = Arrays.copyOfRange(bytes, s, s + n);
        System.arraycopy(snapshot, 0, bytes, t, n);
    }

    private static boolean allZero(byte[] bytes, int start, int end) {
        for (int i = start; i < end; i++) if (bytes[i] != 0) return false;
        return true;
    }

    private static byte[] decrypt(byte[] key, byte[] bytes) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
            return cipher.doFinal(bytes);
        }
        catch (GeneralSecurityException ex) {
            throw new IOException("AES decryption failed", ex);
        }
    }

    private static byte[] digest(String algorithm, byte[] bytes) {
        try { return MessageDigest.getInstance(algorithm).digest(bytes); }
        catch (GeneralSecurityException ex) { throw new IllegalStateException(ex); }
    }

    private static int checkedInt(long value, String what) throws IOException {
        if (value < 0 || value > Integer.MAX_VALUE) throw bad(what + " exceeds signed Java bounds");
        return (int)value;
    }

    private static void range(long offset, long size, long limit, String what) throws IOException {
        if (offset < 0 || size < 0 || offset > limit || size > limit - offset)
            throw bad(what + " outside bounds: offset=" + hex(offset)
                + " size=" + hex(size) + " limit=" + hex(limit));
    }

    private static void putBe16(byte[] bytes, int p, int value) throws IOException {
        range(p, 2, bytes.length, "BE16 write");
        bytes[p] = (byte)(value >>> 8);
        bytes[p + 1] = (byte)value;
    }

    private static String hex(long value) { return String.format("0x%X", value); }
    private static IOException bad(String message) { return new IOException(message); }

    private static final class Reader {
        final byte[] data;
        Reader(byte[] data) { this.data = data; }
        void range(long p, long n, String what) throws IOException {
            XexPatch.range(p, n, data.length, what);
        }
        int u8(long p) throws IOException {
            range(p, 1, "byte"); return data[(int)p] & 255;
        }
        int be16(long p) throws IOException { return u8(p) << 8 | u8(p + 1); }
        long be32(long p) throws IOException { return (long)be16(p) << 16 | be16(p + 2); }
        byte[] bytes(long p, int n) throws IOException {
            range(p, n, "byte array");
            return Arrays.copyOfRange(data, (int)p, (int)p + n);
        }
    }
}
