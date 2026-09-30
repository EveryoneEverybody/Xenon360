package xenon360.xex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Xenon XEX container-to-image parser for XEX0 through XEX2 generations. */
public final class XexImage {
    public static final int MAX_FILE_BYTES = 256 * 1024 * 1024;
    public static final int MAX_IMAGE_BYTES = 512 * 1024 * 1024;
    public static final String VERSION = "0.7.0";
    private static final long FORMAT = 0x000003ffL, ENTRY = 0x00010100L;
    private static final long BASE = 0x00010201L, IMPORTS = 0x000103ffL;
    private static final long IMPORTS_PREXEX2 = 0x000102ffL;
    private static final long SECTION_TABLE_BETA = 0x000001ffL;
    private static final byte[] RETAIL = HexFormat.of().parseHex("20b185a59d28fdc340583fbb0896bf91");
    private static final byte[] RETAIL_XEX1 = HexFormat.of().parseHex("a26c10f71fd935e98b99922ce9321572");
    private static final byte[] DEVKIT_XEX1 = HexFormat.of().parseHex("a8b00512ede3638dc658b3101f9f50d1");
    private record MasterKey(String name, byte[] key) { }
    private static final List<MasterKey> MASTER_KEYS = List.of(
        new MasterKey("retail", RETAIL), new MasterKey("devkit", new byte[16]),
        new MasterKey("retail-XEX1", RETAIL_XEX1), new MasterKey("devkit-XEX1", DEVKIT_XEX1));

    public record Section(String name, String peName, long rva, int size, long rawSize,
                          long rawPointer, long flags, int availableBytes) {
        public boolean read() { return (flags & 0x40000000L) != 0; }
        public boolean write() { return (flags & 0x80000000L) != 0; }
        public boolean execute() { return (flags & 0x20000000L) != 0; }
        public int syntheticTailBytes() { return size - availableBytes; }
    }
    public record ImportRecord(long address, long rawWord, int kind, int ordinal, String symbolName) {
        public ImportRecord(long address, long rawWord, int kind, int ordinal) {
            this(address, rawWord, kind, ordinal, null);
        }
        public boolean named() { return symbolName != null && !symbolName.isBlank(); }
    }
    public record LibraryGroup(String name, int nameIndexRaw, long version,
                               long minimumVersion, List<ImportRecord> records) { }
    public record PdataRecord(long entry, long packedInfo) { }
    public record CodeViewInfo(String signature, String guid, long age, String path) { }
    private record Span(long offset, long size, long value, boolean inline) { }
    private record Basic(int data, int zero) { }
    private record Normal(int windowSize, int firstBlockSize, byte[] firstBlockHash) { }
    private record NormalPayload(byte[] lzx, int blockCount, int trailingBytes) { }
    private record Header(String containerMagic, long base, long entry, int payload, int imageSize,
                          int encryption, int compression, byte[] fileKey,
                          List<Basic> blocks, Normal normal, Map<Long, Span> optional) { }

    public final byte[] image;
    public final String containerMagic;
    public final long imageBase, entryPoint, peImageBase, peSizeOfImage, expandedBytes;
    public final int compression, encryption;
    public final int normalWindowSize, normalBlockCount, normalLzxBytes, normalTrailingBytes;
    public final String keyKind, sourceSha256;
    public final List<Section> sections;
    public final List<LibraryGroup> libraries;
    public final List<PdataRecord> pdata;
    public final CodeViewInfo codeView;
    public final List<String> warnings;

    private XexImage(byte[] image, Header h, long peImageBase, long peSize, long expanded, String keyKind,
                     String sourceHash, int normalBlockCount, int normalLzxBytes, int normalTrailingBytes,
                     List<Section> sections, List<LibraryGroup> libraries,
                     List<PdataRecord> pdata, CodeViewInfo codeView, List<String> warnings) {
        this.image = image; containerMagic = h.containerMagic;
        imageBase = h.base; entryPoint = h.entry; this.peImageBase = peImageBase;
        peSizeOfImage = peSize; expandedBytes = expanded;
        compression = h.compression; encryption = h.encryption;
        normalWindowSize = h.normal == null ? 0 : h.normal.windowSize;
        this.normalBlockCount = normalBlockCount; this.normalLzxBytes = normalLzxBytes;
        this.normalTrailingBytes = normalTrailingBytes;
        this.keyKind = keyKind; sourceSha256 = sourceHash;
        this.sections = List.copyOf(sections); this.libraries = List.copyOf(libraries);
        this.pdata = List.copyOf(pdata); this.codeView = codeView;
        this.warnings = List.copyOf(warnings);
    }

    public static boolean recognizes(byte[] bytes) {
        return bytes.length >= 4 && bytes[0] == 'X' && bytes[1] == 'E'
            && bytes[2] == 'X' && (bytes[3] == '0' || bytes[3] == '1' || bytes[3] == '2'
                || bytes[3] == '-' || bytes[3] == '%' || bytes[3] == '?');
    }

    public static XexImage parse(byte[] file) throws IOException {
        if (file.length > MAX_FILE_BYTES) throw bad("XEX file exceeds 256 MiB prototype limit");
        Header h = header(file);
        byte[] payload = Arrays.copyOfRange(file, h.payload, file.length);
        if (h.encryption == 0) return assemble(file, h, payload, "none");
        if ((payload.length & 15) != 0) throw bad("AES payload length is not a multiple of 16");
        List<String> failures = new ArrayList<>();
        for (MasterKey master : MASTER_KEYS) {
            byte[] session = null;
            try {
                session = decrypt(master.key, h.fileKey);
                return assemble(file, h, decrypt(session, payload), master.name);
            }
            catch (IOException ex) { failures.add(master.name + ": " + ex.getMessage()); }
            finally { if (session != null) Arrays.fill(session, (byte) 0); }
        }
        throw bad("XEX reconstruction rejected; " + String.join("; ", failures));
    }

    private static Header header(byte[] file) throws IOException {
        Reader r = new Reader(file);
        r.range(0, 4, "fixed header magic");
        if (!recognizes(file)) throw bad("Expected XEX0, XEX?, XEX%, XEX-, XEX1, or XEX2 signature");
        String containerMagic = new String(file, 0, 4, StandardCharsets.US_ASCII);
        boolean xex0 = containerMagic.equals("XEX0");
        boolean xex3f = containerMagic.equals("XEX?");
        boolean xex25 = containerMagic.equals("XEX%");
        boolean xex1 = containerMagic.equals("XEX1");
        boolean xex2d = containerMagic.equals("XEX-");

        long payload, security = 0, count, optionalStart, base = 0, imageSize = 0;
        if (xex0) {
            r.range(0, 20, "XEX0 fixed header");
            payload = r.be32(4);
            base = r.be32(8);
            imageSize = r.be32(12);
            count = r.be32(16);
            optionalStart = 20;
        }
        else if (xex3f) {
            r.range(0, 28, "XEX? fixed header");
            payload = r.be32(8);
            base = r.be32(16);
            imageSize = r.be32(20);
            count = r.be32(24);
            optionalStart = 28;
        }
        else {
            r.range(0, 24, "fixed header");
            if (!xex2d && (r.be32(4) & 0x70) != 0)
                throw bad("XEX patch modules must use the XEXP patch path");
            payload = r.be32(8);
            security = r.be32(16);
            count = r.be32(20);
            optionalStart = 24;
        }

        if (count > 4096) throw bad("Optional header count exceeds 4096");
        within(optionalStart, count * 8, payload, "optional table");
        r.range(payload, 0, "payload offset");
        Map<Long, Span> optional = new LinkedHashMap<>();
        for (int i = 0; i < count; i++) {
            long key = r.be32(optionalStart + 8L * i), value = r.be32(optionalStart + 4 + 8L * i);
            int tag = (int)(key & 255);
            boolean inline = tag <= 1;
            long size = inline ? 4 : tag == 255 ? r.be32(value) : tag * 4L;
            if (!inline) {
                if (size < 4) throw bad("Optional header is shorter than one word");
                within(value, size, payload, "optional header " + hex(key));
                r.range(value, size, "optional header");
            }
            if (optional.put(key, new Span(value, size, value, inline)) != null)
                throw bad("Duplicate optional header " + hex(key));
        }

        int imageLength;
        int encryption = 0, compression = 0;
        byte[] fileKey = new byte[16];
        List<Basic> blocks = new ArrayList<>();
        Normal normal = null;
        long entry = optional.containsKey(ENTRY) ? optional.get(ENTRY).value : 0;

        if (xex0 || xex3f) {
            imageLength = limitedSize(imageSize, containerMagic + " image size");
            if (base + imageSize > 0x100000000L)
                throw bad(containerMagic + " image wraps 32-bit address space");
            if (xex3f) {
                Span betaSections = optional.get(SECTION_TABLE_BETA);
                if (betaSections == null || betaSections.inline || betaSections.size < 4
                        || (betaSections.size - 4) % 32 != 0)
                    throw bad("Missing/invalid XEX? section table");
            }
            return new Header(containerMagic, base, entry, (int)payload, imageLength,
                0, 0, fileKey, blocks, null, optional);
        }

        long securityFixed = xex2d ? 0x140 : xex25 ? 0x154 : xex1 ? 0x168 : 0x184;
        long descriptorCountOffset = xex2d ? 0x13c : xex25 ? 0x150 : xex1 ? 0x164 : 0x180;
        long descriptorTableOffset = xex2d ? 0x140 : xex25 ? 0x154 : xex1 ? 0x168 : 0x184;
        long imageFlagsOffset = xex2d ? 0x13e : xex25 ? 0x144 : xex1 ? 0x158 : 0x10c;
        long loadAddressOffset = xex2d ? 0x12c : xex25 || xex1 ? 0x130 : 0x110;
        long fileKeyOffset = xex25 || xex1 ? 0x134 : 0x150;
        within(security, securityFixed, payload, "security header");
        long securitySize = r.be32(security);
        imageSize = r.be32(security + (xex2d ? 0x130 : 4));
        imageLength = limitedSize(imageSize, "security image size");
        within(security, securitySize, payload, "security span");
        long descriptors = xex2d ? r.be16(security + descriptorCountOffset)
            : r.be32(security + descriptorCountOffset);
        if (descriptors > 1048576) throw bad("Excessive page descriptor count");
        within(descriptorTableOffset, descriptors * 24, securitySize, "page descriptors");
        long pageSize = xex2d ? 4096
            : (r.be32(security + imageFlagsOffset) & 0x10000000L) != 0 ? 4096 : 65536;
        long descriptorBytes = 0;
        for (int i = 0; i < descriptors; i++) {
            long raw = r.be32(security + descriptorTableOffset + i * 24L);
            long spanBytes = (raw >>> 4) * pageSize;
            if (spanBytes > imageSize - descriptorBytes)
                throw bad("Descriptor size exceeds security image size");
            descriptorBytes += spanBytes;
        }
        if (descriptorBytes != imageSize) throw bad("Descriptor size differs from security image size");
        base = optional.containsKey(BASE) ? optional.get(BASE).value : r.be32(security + loadAddressOffset);
        if (base + imageSize > 0x100000000L) throw bad("XEX image wraps 32-bit address space");

        Span f = optional.get(FORMAT);
        if (f == null || f.inline || f.size < 8) throw bad("Missing/short file-format header");
        encryption = r.be16(f.offset + 4);
        compression = r.be16(f.offset + 6);
        if (encryption > 1) throw bad("Unsupported encryption type " + encryption);
        if (xex2d && encryption != 0)
            throw bad("Encrypted XEX- is unsupported: legacy security info has no image key");
        if (compression > 2) throw bad("Unsupported compression type " + compression
            + " (supports NONE, BASIC, and NORMAL/LZX; DELTA uses the XEXP path)");

        long dataTotal = 0, expanded = 0;
        if (compression == 1) {
            if ((f.size - 8) % 8 != 0 || f.size == 8) throw bad("Invalid BASIC block table");
            for (long q = f.offset + 8; q < f.offset + f.size; q += 8) {
                long data = r.be32(q), zero = r.be32(q + 4);
                if (data > MAX_IMAGE_BYTES || zero > MAX_IMAGE_BYTES) throw bad("BASIC block exceeds limit");
                if (encryption == 1 && (data & 15) != 0) throw bad("Encrypted BASIC block is unaligned");
                dataTotal += data; expanded += data + zero;
                if (expanded > imageSize) throw bad("BASIC expansion exceeds security image");
                blocks.add(new Basic((int)data, (int)zero));
            }
            long payloadBytes = file.length - payload;
            if (dataTotal > payloadBytes) throw bad("BASIC data total exceeds payload size");
            if (dataTotal != payloadBytes) {
                if (!xex2d) throw bad("BASIC data total differs from payload size");
                if (!allZero(file, (int)(payload + dataTotal), file.length))
                    throw bad("XEX- has nonzero bytes after BASIC basefile");
            }
        }
        else if (compression == 2) {
            if (f.size < 36) throw bad("Short NORMAL/LZX file-format header");
            long window = r.be32(f.offset + 8), firstBlock = r.be32(f.offset + 12);
            if (window < (1 << 15) || window > (1 << 21) || (window & (window - 1)) != 0)
                throw bad("Invalid NORMAL/LZX window size " + hex(window));
            if (firstBlock < 24 || firstBlock > file.length - payload)
                throw bad("Invalid NORMAL/LZX first block size " + hex(firstBlock));
            normal = new Normal((int)window, (int)firstBlock,
                Arrays.copyOfRange(file, (int)f.offset + 16, (int)f.offset + 36));
        }
        else if (file.length - payload > imageSize) throw bad("Uncompressed payload exceeds image size");

        if (!xex2d)
            fileKey = Arrays.copyOfRange(file, (int)(security + fileKeyOffset),
                (int)(security + fileKeyOffset + 16));
        return new Header(containerMagic, base, entry, (int)payload, imageLength,
            encryption, compression, fileKey, blocks, normal, optional);
    }

    private static XexImage assemble(byte[] file, Header h, byte[] plain, String keyKind)
            throws IOException {
        byte[] image;
        int dst = 0, ignoredPayloadBytes = 0, normalBlockCount = 0, normalLzxBytes = 0, normalTrailingBytes = 0;
        if (h.containerMagic.equals("XEX0")) {
            image = normalizeXex0Image(file, h);
            dst = image.length;
        }
        else if (h.containerMagic.equals("XEX?")) {
            image = normalizeEarlyRawImage(file, h);
            dst = image.length;
        }
        else if (h.compression == 0) {
            image = new byte[h.imageSize];
            System.arraycopy(plain, 0, image, 0, plain.length);
            dst = plain.length;
        }
        else if (h.compression == 1) {
            image = new byte[h.imageSize];
            int src = 0;
            for (Basic b : h.blocks) {
                System.arraycopy(plain, src, image, dst, b.data);
                src += b.data; dst += b.data + b.zero;
            }
            ignoredPayloadBytes = plain.length - src;
        }
        else {
            NormalPayload normal = normalPayload(plain, h.normal);
            image = new XenonLzxDecoder(h.normal.windowSize).decompress(normal.lzx, h.imageSize);
            dst = image.length;
            normalBlockCount = normal.blockCount;
            normalLzxBytes = normal.lzx.length;
            normalTrailingBytes = normal.trailingBytes;
        }
        Reader r = new Reader(image);
        r.range(0, 64, "DOS header");
        if (r.le16(0) != 0x5a4d) throw bad("Decrypted image has no MZ signature");
        long pe = r.le32(0x3c);
        r.range(pe, 24, "PE header");
        if (r.le32(pe) != 0x4550) throw bad("Invalid PE signature");
        if (r.le16(pe + 4) != 0x1f2) throw bad("Expected Xbox PowerPC machine 0x01F2");
        int count = r.le16(pe + 6), optSize = r.le16(pe + 20);
        if (count < 1 || count > 512 || optSize < 96) throw bad("Invalid PE header sizes");
        long opt = pe + 24;
        r.range(opt, optSize, "PE optional header");
        if (r.le16(opt) != 0x10b) throw bad("Expected PE32 optional header");
        long peImageBase = r.le32(opt + 28);
        List<String> warnings = new ArrayList<>();
        if (ignoredPayloadBytes != 0)
            warnings.add(h.containerMagic + ": ignored " + ignoredPayloadBytes
                + " trailing zero padding bytes after BASIC basefile");
        if (peImageBase != h.base)
            warnings.add("PE preferred ImageBase " + hex(peImageBase)
                + " differs from XEX load base " + hex(h.base)
                + "; mapping uses XEX load base");
        long peSize = r.le32(opt + 56), headersSize = r.le32(opt + 60);
        limitedSize(peSize, "PE SizeOfImage");
        r.range(0, headersSize, "PE SizeOfHeaders");
        long peEntryRva = r.le32(opt + 16);
        long entry = h.entry != 0 ? h.entry : peEntryRva == 0 ? 0 : h.base + peEntryRva;
        if (h.entry != 0 && h.base + peEntryRva != entry) throw bad("XEX and PE entry points differ");
        long table = opt + optSize;
        within(table, count * 40L, headersSize, "PE section table");
        List<Section> sections = new ArrayList<>();
        Map<String, Integer> nameCounts = new HashMap<>();
        for (int i = 0; i < count; i++) {
            long p = table + i * 40L;
            String peName = r.ascii(p, 8);
            if (peName.isEmpty()) throw bad("Empty PE section name");
            int occurrence = nameCounts.merge(peName, 1, Integer::sum);
            String name = occurrence == 1 ? peName : peName + "#" + occurrence;
            if (occurrence > 1)
                warnings.add("Duplicate PE section name " + peName + " mapped as " + name);
            long size = r.le32(p + 8), rva = r.le32(p + 12);
            within(rva, size, peSize, "section " + name);
            if (h.base + rva + size > 0x100000000L) throw bad("Section wraps address space");
            int available = rva >= image.length ? 0 : (int)Math.min(size, image.length - rva);
            Section s = new Section(name, peName, rva, (int)size, r.le32(p + 16),
                r.le32(p + 20), r.le32(p + 36), available);
            if (s.syntheticTailBytes() > 0) warnings.add(name + ": " + s.syntheticTailBytes()
                + " bytes beyond XEX image will be synthetic zeros; not recovered source bytes");
            sections.add(s);
        }
        if (h.containerMagic.equals("XEX?"))
            addEarlyRawExtraSections(file, h, image, sections, count, warnings);
        List<Section> sorted = new ArrayList<>(sections);
        sorted.sort(Comparator.comparingLong(Section::rva));
        long end = 0;
        for (Section s : sorted) {
            if (s.size == 0) continue;
            if (s.rva < end) throw bad("Overlapping PE section " + s.name);
            end = s.rva + s.size;
        }
        Header effective = new Header(h.containerMagic, h.base, entry, h.payload, h.imageSize, h.encryption,
            h.compression, h.fileKey, h.blocks, h.normal, h.optional);
        if (entry != 0 && !inSection(sections, entry - h.base, 4, true))
            throw bad("Entry point is not in executable bytes");
        CodeViewInfo codeView = readCodeView(image, opt, optSize, warnings);
        List<LibraryGroup> libraries = (h.containerMagic.equals("XEX0") || h.containerMagic.equals("XEX?"))
            ? peImportsEarlyRaw(image, effective, sections, warnings)
            : imports(file, effective, image, sections, warnings);
        List<PdataRecord> pdata = new ArrayList<>();
        for (Section s : sections) if (s.name.equals(".pdata")) {
            if (s.availableBytes != s.size || s.size % 8 != 0) throw bad("Truncated/misaligned .pdata");
            for (long p = s.rva; p < s.rva + s.size; p += 8)
                pdata.add(new PdataRecord(r.be32(p), r.be32(p + 4)));
        }
        return new XexImage(image, effective, peImageBase, peSize, dst, keyKind, sha256(file),
            normalBlockCount, normalLzxBytes, normalTrailingBytes, sections, libraries, pdata,
            codeView, warnings);
    }

    private static byte[] normalizeXex0Image(byte[] file, Header h) throws IOException {
        Reader fr = new Reader(file);
        int peOffset = h.payload;
        fr.range(peOffset, 64, "XEX0 PE header");
        if (fr.le16(peOffset) != 0x5a4d) throw bad("XEX0 payload has no MZ signature");
        long pe = peOffset + fr.le32(peOffset + 0x3c);
        fr.range(pe, 24, "XEX0 PE header");
        if (fr.le32(pe) != 0x4550) throw bad("XEX0 payload has invalid PE signature");
        if (fr.le16(pe + 4) != 0x1f2) throw bad("XEX0 expected Xbox PowerPC machine 0x01F2");
        int sectionCount = fr.le16(pe + 6), optSize = fr.le16(pe + 20);
        long opt = pe + 24;
        fr.range(opt, optSize, "XEX0 PE optional header");
        if (fr.le16(opt) != 0x10b) throw bad("XEX0 expected PE32 optional header");
        long peSize = fr.le32(opt + 56), headersSize = fr.le32(opt + 60);
        int imageSize = limitedSize(Math.max((long)h.imageSize, peSize), "XEX0 normalized image size");
        byte[] image = new byte[imageSize];
        long headerCopy = Math.min(headersSize, file.length - (long)peOffset);
        within(0, headerCopy, image.length, "XEX0 normalized PE headers");
        System.arraycopy(file, peOffset, image, 0, (int)headerCopy);

        long table = opt + optSize;
        fr.range(table, sectionCount * 40L, "XEX0 PE section table");
        for (int i = 0; i < sectionCount; i++) {
            long q = table + i * 40L;
            long virtualSize = fr.le32(q + 8), rva = fr.le32(q + 12);
            long rawSize = fr.le32(q + 16), rawPointer = fr.le32(q + 20);
            long copy = Math.min(virtualSize, rawSize);
            within(rva, virtualSize, image.length, "XEX0 section virtual span");
            if (copy != 0) {
                long source = h.payload + rawPointer;
                fr.range(source, copy, "XEX0 section raw span");
                System.arraycopy(file, (int)source, image, (int)rva, (int)copy);
            }
        }
        return image;
    }

    private static byte[] normalizeEarlyRawImage(byte[] file, Header h) throws IOException {
        Reader fr = new Reader(file);
        Span span = h.optional.get(SECTION_TABLE_BETA);
        int count = (int)((span.size - 4) / 32);
        long peSize = 0;
        int peOffset = h.payload;
        fr.range(peOffset, 64, h.containerMagic + " PE header");
        if (fr.le16(peOffset) != 0x5a4d) throw bad(h.containerMagic + " payload has no MZ signature");
        long pe = peOffset + fr.le32(peOffset + 0x3c);
        fr.range(pe, 24, h.containerMagic + " PE header");
        if (fr.le32(pe) != 0x4550) throw bad(h.containerMagic + " payload has invalid PE signature");
        long opt = pe + 24;
        int optSize = fr.le16(pe + 20);
        fr.range(opt, optSize, h.containerMagic + " PE optional header");
        peSize = fr.le32(opt + 56);
        int imageSize = limitedSize(Math.max((long)h.imageSize, peSize), h.containerMagic + " normalized image size");
        byte[] image = new byte[imageSize];

        for (int i = 0; i < count; i++) {
            long q = span.offset + 4 + i * 32L;
            long rva = fr.be32(q + 8), virtualSize = fr.be32(q + 12);
            long rawPointer = fr.be32(q + 16), rawSize = fr.be32(q + 20);
            long copy = Math.min(virtualSize, rawSize);
            within(rva, virtualSize, image.length, h.containerMagic + " section virtual span");
            if (copy != 0) {
                fr.range(rawPointer, copy, h.containerMagic + " section raw span");
                System.arraycopy(file, (int)rawPointer, image, (int)rva, (int)copy);
            }
        }
        return image;
    }

    private static void addEarlyRawExtraSections(byte[] file, Header h, byte[] image,
            List<Section> sections, int peSectionCount, List<String> warnings) throws IOException {
        Span span = h.optional.get(SECTION_TABLE_BETA);
        if (span == null) return;
        Reader fr = new Reader(file);
        int total = (int)((span.size - 4) / 32);
        for (int i = peSectionCount; i < total; i++) {
            long q = span.offset + 4 + i * 32L;
            String rawName = fr.ascii(q, 8);
            if (rawName.isEmpty()) rawName = "xex3f_section_" + i;
            String name = rawName;
            int suffix = 2;
            while (containsSectionName(sections, name)) name = rawName + "#" + suffix++;
            long rva = fr.be32(q + 8), virtualSize = fr.be32(q + 12);
            long rawPointer = fr.be32(q + 16), rawSize = fr.be32(q + 20);
            long pageFlags = fr.be32(q + 24);
            within(rva, virtualSize, image.length, h.containerMagic + " extra section " + name);
            long flags = 0x40000000L;
            if ((pageFlags & 1) == 0) flags |= 0x80000000L;
            if ((pageFlags & 2) == 0) flags |= 0x20000000L;
            int available = (int)Math.min(virtualSize, rawSize);
            int sameRva = -1;
            for (int j = 0; j < sections.size(); j++) {
                Section existing = sections.get(j);
                long a0 = existing.rva, a1 = existing.rva + existing.size;
                long b0 = rva, b1 = rva + virtualSize;
                if (existing.rva == rva) sameRva = j;
                else if (a0 < b1 && b0 < a1)
                    throw bad(h.containerMagic + " extra section partially overlaps PE section " + existing.name);
            }
            Section mapped = new Section(name, rawName, rva, (int)virtualSize, rawSize,
                rawPointer, flags, available);
            if (sameRva >= 0) {
                Section prior = sections.get(sameRva);
                sections.set(sameRva, mapped);
                warnings.add(h.containerMagic + " resource " + rawName + " overlays PE section "
                    + prior.peName + " at " + hex(rva) + "; mapped as " + name);
            }
            else {
                sections.add(mapped);
                warnings.add(h.containerMagic + " extra section " + rawName + " mapped from legacy section table");
            }
        }
    }

    private static boolean containsSectionName(List<Section> sections, String name) {
        for (Section section : sections) if (section.name.equals(name)) return true;
        return false;
    }


    private static CodeViewInfo readCodeView(byte[] image, long opt, int optSize,
            List<String> warnings) throws IOException {
        Reader r = new Reader(image);
        if (optSize < 96 + 7 * 8) return null;
        long directoryCount = r.le32(opt + 92);
        if (directoryCount <= 6) return null;
        long debugRva = r.le32(opt + 96 + 6 * 8L);
        long debugSize = r.le32(opt + 100 + 6 * 8L);
        if (debugRva == 0 || debugSize == 0) return null;
        if (debugSize % 28 != 0)
            warnings.add("PE debug directory size is not a multiple of 28 bytes");
        within(debugRva, debugSize, image.length, "PE debug directory");

        CodeViewInfo found = null;
        long end = debugRva + debugSize;
        for (long p = debugRva; p + 28 <= end; p += 28) {
            long type = r.le32(p + 12);
            long size = r.le32(p + 16);
            long address = r.le32(p + 20);
            if (type != 2 || size < 4 || address == 0) continue;
            within(address, size, image.length, "CodeView record");
            String signature = new String(image, (int)address, 4, StandardCharsets.US_ASCII);
            if (!signature.equals("RSDS")) {
                warnings.add("Unsupported CodeView signature " + signature + " at " + hex(address));
                continue;
            }
            if (size < 24) throw bad("Short RSDS CodeView record");
            String guid = String.format(Locale.ROOT,
                "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                r.le32(address + 4), r.le16(address + 8), r.le16(address + 10),
                r.u8(address + 12), r.u8(address + 13), r.u8(address + 14),
                r.u8(address + 15), r.u8(address + 16), r.u8(address + 17),
                r.u8(address + 18), r.u8(address + 19));
            long age = r.le32(address + 20);
            long pathStart = address + 24;
            long pathEnd = address + size;
            int length = 0;
            while (pathStart + length < pathEnd && r.u8(pathStart + length) != 0) length++;
            String path = length == 0 ? "" :
                new String(image, (int)pathStart, length, StandardCharsets.UTF_8);
            CodeViewInfo current = new CodeViewInfo(signature, guid, age, path);
            if (found != null && !found.equals(current))
                throw bad("Multiple conflicting RSDS CodeView records");
            found = current;
        }
        return found;
    }

    private static List<LibraryGroup> peImportsEarlyRaw(byte[] image, Header h,
            List<Section> sections, List<String> warnings) throws IOException {
        Reader r = new Reader(image);
        r.range(0, 64, h.containerMagic + " normalized DOS header");
        long pe = r.le32(0x3c);
        r.range(pe, 24, h.containerMagic + " normalized PE header");
        long opt = pe + 24;
        int optSize = r.le16(pe + 20);
        r.range(opt, optSize, h.containerMagic + " normalized PE optional header");
        if (optSize < 112 || r.le32(opt + 92) < 2) return List.of();
        long importRva = r.le32(opt + 104), importSize = r.le32(opt + 108);
        if (importRva == 0 || importSize == 0) return List.of();
        within(importRva, importSize, image.length, h.containerMagic + " PE import directory");

        List<LibraryGroup> groups = new ArrayList<>();
        long end = importRva + importSize;
        int descriptorIndex = 0;
        for (long p = importRva; p + 20 <= end; p += 20) {
            long originalThunk = r.le32(p), timestamp = r.le32(p + 4);
            long forwarder = r.le32(p + 8), nameRva = r.le32(p + 12), firstThunk = r.le32(p + 16);
            if ((originalThunk | timestamp | forwarder | nameRva | firstThunk) == 0) break;
            if (nameRva == 0 || firstThunk == 0) throw bad("Malformed " + h.containerMagic + " PE import descriptor");
            String library = asciiZ(r, nameRva, 256, h.containerMagic + " PE import library");
            long lookup = originalThunk != 0 ? originalThunk : firstThunk;
            List<ImportRecord> records = new ArrayList<>();
            boolean terminated = false;
            for (int i = 0; i < 65536; i++) {
                long slot = lookup + i * 4L;
                r.range(slot, 4, h.containerMagic + " PE import lookup");
                long raw = r.le32(slot);
                if (raw == 0) { terminated = true; break; }
                int ordinal = -1;
                String symbolName = null;
                if ((raw & 0x80000000L) != 0) {
                    ordinal = (int)(raw & 0xffff);
                }
                else {
                    r.range(raw, 3, h.containerMagic + " PE import-by-name");
                    symbolName = asciiZ(r, raw + 2, 512, h.containerMagic + " PE import symbol");
                }
                long iatRva = firstThunk + i * 4L;
                if (!inSection(sections, iatRva, 4, false))
                    throw bad(h.containerMagic + " PE IAT slot is outside section bytes: " + hex(iatRva));
                records.add(new ImportRecord(h.base + iatRva, raw, 2, ordinal, symbolName));
            }
            if (!terminated) throw bad("Unterminated " + h.containerMagic + " PE import thunk table");
            groups.add(new LibraryGroup(library, descriptorIndex++, 0, 0, List.copyOf(records)));
        }
        long named = groups.stream().flatMap(g -> g.records().stream()).filter(ImportRecord::named).count();
        warnings.add(h.containerMagic + " imports recovered from PE import directory; kind=2 denotes IAT function slots"
            + "; named=" + named);
        return List.copyOf(groups);
    }

    private static String asciiZ(Reader r, long p, int max, String what) throws IOException {
        if (p < 0 || p >= r.data.length) throw bad(what + " outside bounds");
        int n = 0;
        while (n < max && p + n < r.data.length && r.data[(int)p + n] != 0) {
            int c = r.data[(int)p + n] & 255;
            if (c < 32 || c > 126) throw bad(what + " contains non-ASCII bytes");
            n++;
        }
        if (n == 0 || n == max || p + n >= r.data.length) throw bad(what + " is empty or unterminated");
        return new String(r.data, (int)p, n, StandardCharsets.US_ASCII);
    }

    private static List<LibraryGroup> imports(byte[] file, Header h, byte[] image,
            List<Section> sections, List<String> warnings) throws IOException {
        boolean oldImportKey = (h.containerMagic.equals("XEX-") || h.containerMagic.equals("XEX%"))
            && !h.optional.containsKey(IMPORTS);
        boolean shortImportHeader = h.containerMagic.equals("XEX-");
        Span span = h.optional.get(oldImportKey ? IMPORTS_PREXEX2 : IMPORTS);
        if (span == null) return List.of();
        Reader r = new Reader(file), ir = new Reader(image);
        if (span.size < 12) throw bad("Short import header");
        long stringsSize = r.be32(span.offset + 4), stringsCount = r.be32(span.offset + 8);
        within(12, stringsSize, span.size, "import strings");
        if (stringsCount > 4096) throw bad("Excessive import library count");
        List<String> names = new ArrayList<>();
        long p = span.offset + 12, stringEnd = p + stringsSize;
        for (int i = 0; i < stringsCount; i++) {
            long start = p;
            while (p < stringEnd && r.u8(p) != 0) p++;
            if (p == stringEnd || p == start) throw bad("Unterminated/empty import library name");
            names.add(r.ascii(start, (int)(p - start)));
            p = span.offset + 12 + ((p - (span.offset + 12) + 4) & ~3L);
        }
        List<LibraryGroup> groups = new ArrayList<>();
        long end = span.offset + span.size;
        for (p = stringEnd; p < end; ) {
            int headerSize = shortImportHeader ? 36 : 40;
            within(p, headerSize, end, "import library header");
            long size = r.be32(p);
            if (size < headerSize) throw bad("Invalid import library size");
            within(p, size, end, "import library span");
            int nameRaw = r.be16(p + (shortImportHeader ? 32 : 36));
            int count = r.be16(p + (shortImportHeader ? 34 : 38)), index = nameRaw & 255;
            if (index >= names.size()) throw bad("Import library name index out of range");
            within(headerSize, count * 4L, size, "import record table");
            List<ImportRecord> records = new ArrayList<>();
            int legacyPrelinked = 0;
            for (int i = 0; i < count; i++) {
                long address = r.be32(p + headerSize + i * 4L), rva = address - h.base;
                if ((address & 3) != 0 || !inSection(sections, rva, 4, false))
                    throw bad("Import record is outside section bytes: " + hex(address));
                ir.range(rva, 4, "import record word");
                long raw = ir.be32(rva);
                int kind = (int)(raw >>> 24);
                int ordinal = kind <= 1 ? (int)(raw & 65535) : -1;
                if (h.containerMagic.equals("XEX%") && kind > 1 && !records.isEmpty()) {
                    ImportRecord previous = records.get(records.size() - 1);
                    if (previous.kind() == 0 && previous.ordinal() > 0) {
                        kind = 1;
                        ordinal = previous.ordinal();
                        warnings.add("XEX% recovered prelinked thunk ordinal " + ordinal
                            + " from preceding import slot at " + hex(previous.address()));
                    }
                }
                if (kind > 1) legacyPrelinked++;
                records.add(new ImportRecord(address, raw, kind, ordinal));
            }
            if (legacyPrelinked != 0)
                warnings.add(h.containerMagic + " import group " + names.get(index)
                    + " contains " + legacyPrelinked
                    + " prelinked/legacy thunk records without recoverable ordinal markers");
            groups.add(new LibraryGroup(names.get(index), nameRaw, r.be32(p + 28),
                shortImportHeader ? 0 : r.be32(p + 32), List.copyOf(records)));
            p += size;
        }
        return groups;
    }

    private static NormalPayload normalPayload(byte[] plain, Normal normal) throws IOException {
        if (normal == null) throw bad("Missing NORMAL/LZX compression metadata");
        Reader r = new Reader(plain);
        java.io.ByteArrayOutputStream lzx = new java.io.ByteArrayOutputStream();
        int offset = 0, blockSize = normal.firstBlockSize, blockCount = 0;
        byte[] expectedHash = normal.firstBlockHash;
        while (blockSize != 0) {
            if (++blockCount > 1048576) throw bad("Excessive NORMAL/LZX block count");
            r.range(offset, blockSize, "NORMAL/LZX block");
            if (blockSize < 24) throw bad("NORMAL/LZX block shorter than metadata header");
            byte[] actualHash = digest("SHA-1", Arrays.copyOfRange(plain, offset, offset + blockSize));
            if (!MessageDigest.isEqual(expectedHash, actualHash))
                throw bad("NORMAL/LZX block SHA-1 mismatch at payload offset " + hex(offset));
            int nextSize = (int)r.be32(offset);
            byte[] nextHash = Arrays.copyOfRange(plain, offset + 4, offset + 24);
            int p = offset + 24, end = offset + blockSize;
            boolean terminated = false;
            while (p < end) {
                if (end - p < 2) throw bad("Truncated NORMAL/LZX chunk length");
                int chunk = r.be16(p); p += 2;
                if (chunk == 0) { terminated = true; break; }
                if (chunk > end - p) throw bad("NORMAL/LZX chunk exceeds containing block");
                if ((long)lzx.size() + chunk > MAX_FILE_BYTES)
                    throw bad("NORMAL/LZX compressed stream exceeds 256 MiB limit");
                lzx.write(plain, p, chunk);
                p += chunk;
            }
            if (!terminated) throw bad("NORMAL/LZX block has no chunk terminator");
            offset += blockSize;
            if (nextSize != 0 && (nextSize < 24 || nextSize > plain.length - offset))
                throw bad("Invalid chained NORMAL/LZX block size " + hex(nextSize));
            blockSize = nextSize;
            expectedHash = nextHash;
        }
        int trailing = plain.length - offset;
        if (trailing < 0) throw bad("NORMAL/LZX block chain exceeds payload");
        return new NormalPayload(lzx.toByteArray(), blockCount, trailing);
    }

    public boolean executable(long address, int length) {
        return inSection(sections, address - imageBase, length, true);
    }
    private static boolean inSection(List<Section> sections, long rva, long length, boolean exec) {
        if (rva < 0) return false;
        for (Section s : sections) if ((!exec || s.execute()) && rva >= s.rva
                && rva - s.rva <= s.availableBytes && length <= s.availableBytes - (rva - s.rva)) return true;
        return false;
    }
    /** Section view preserving the available prefix; tail zeros are explicitly synthetic. */
    public byte[] sectionBytes(Section section) {
        byte[] bytes = new byte[section.size];
        if (section.availableBytes != 0)
            System.arraycopy(image, (int)section.rva, bytes, 0, section.availableBytes);
        return bytes;
    }
    public static String sha256(byte[] bytes) {
        return HexFormat.of().formatHex(digest("SHA-256", bytes));
    }
    private static byte[] digest(String algorithm, byte[] bytes) {
        try { return MessageDigest.getInstance(algorithm).digest(bytes); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
    private static byte[] decrypt(byte[] key, byte[] bytes) throws IOException {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
            return cipher.doFinal(bytes);
        }
        catch (GeneralSecurityException ex) { throw new IOException("AES decryption failed", ex); }
    }
    private static int limitedSize(long size, String what) throws IOException {
        if (size < 64 || size > MAX_IMAGE_BYTES) throw bad(what + " exceeds 512 MiB limit or is too small");
        return (int)size;
    }
    private static void within(long offset, long size, long limit, String what) throws IOException {
        if (offset < 0 || size < 0 || offset > limit || size > limit - offset)
            throw bad(what + " outside bounds: offset=" + hex(offset) + " size=" + hex(size) + " limit=" + hex(limit));
    }
    private static boolean allZero(byte[] bytes, int start, int end) {
        for (int i = start; i < end; i++) if (bytes[i] != 0) return false;
        return true;
    }
    private static IOException bad(String message) { return new IOException(message); }
    private static String hex(long value) { return String.format("0x%X", value); }
    private static final class Reader {
        final byte[] data;
        Reader(byte[] data) { this.data = data; }
        void range(long p, long n, String what) throws IOException { within(p, n, data.length, what); }
        int u8(long p) throws IOException { range(p, 1, "byte"); return data[(int)p] & 255; }
        int be16(long p) throws IOException { return u8(p) << 8 | u8(p + 1); }
        int le16(long p) throws IOException { return u8(p) | u8(p + 1) << 8; }
        long be32(long p) throws IOException { return (long)be16(p) << 16 | be16(p + 2); }
        long le32(long p) throws IOException { return le16(p) | (long)le16(p + 2) << 16; }
        String ascii(long p, int n) throws IOException {
            range(p, n, "ASCII field"); int len = 0;
            while (len < n && data[(int)p + len] != 0) {
                int c = data[(int)p + len] & 255;
                if (c < 32 || c > 126) throw bad("Non-ASCII name");
                len++;
            }
            return new String(data, (int)p, len, StandardCharsets.US_ASCII);
        }
    }
}
