package xenon360.xex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Standalone synthetic fixtures, no game bytes, Ghidra, network, or third-party importer. */
public final class XexImageSelfTest {
    private static int checks;
    private static final int PAYLOAD = 0x1000, SECURITY = 0x100, FORMAT = 0x300, IMPORTS = 0x340;
    private static final byte[] RETAIL = HexFormat.of().parseHex("20b185a59d28fdc340583fbb0896bf91");
    private static final byte[] SESSION = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f");
    private static void be(byte[] a, int p, long n) { ByteBuffer.wrap(a).order(ByteOrder.BIG_ENDIAN).putInt(p, (int)n); }
    private static void le(byte[] a, int p, long n) { ByteBuffer.wrap(a).order(ByteOrder.LITTLE_ENDIAN).putInt(p, (int)n); }
    private static void be16(byte[] a, int p, int n) { ByteBuffer.wrap(a).order(ByteOrder.BIG_ENDIAN).putShort(p, (short)n); }
    private static void le16(byte[] a, int p, int n) { ByteBuffer.wrap(a).order(ByteOrder.LITTLE_ENDIAN).putShort(p, (short)n); }
    private static void str(byte[] a, int p, String s) {
        byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, a, p, bytes.length);
    }
    private static byte[] crypt(byte[] key, byte[] bytes) throws Exception {
        Cipher c = Cipher.getInstance("AES/CBC/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(new byte[16]));
        return c.doFinal(bytes);
    }
    private static void optional(byte[] file, int i, long key, long value) {
        be(file, 24 + 8*i, key); be(file, 28 + 8*i, value);
    }
    private static int bitAcc, bitCount;
    private static void putBits(ByteArrayOutputStream out, int value, int count) {
        for (int i = count - 1; i >= 0; i--) {
            bitAcc = bitAcc << 1 | (value >>> i & 1);
            if (++bitCount == 16) {
                out.write(bitAcc & 255); out.write(bitAcc >>> 8 & 255);
                bitAcc = 0; bitCount = 0;
            }
        }
    }
    private static void alignBits(ByteArrayOutputStream out) {
        while (bitCount != 0) putBits(out, 0, 1);
    }
    private static void le32(ByteArrayOutputStream out, int value) {
        out.write(value); out.write(value >>> 8); out.write(value >>> 16); out.write(value >>> 24);
    }
    private static byte[] lzxUncompressed(byte[] raw) {
        bitAcc = 0; bitCount = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        putBits(out, 0, 1);                // no Intel E8 translation
        putBits(out, 3, 3);                // UNCOMPRESSED block
        putBits(out, raw.length, 24);
        alignBits(out);
        le32(out, 1); le32(out, 1); le32(out, 1);
        out.writeBytes(raw);
        if ((raw.length & 1) != 0) out.write(0);
        return out.toByteArray();
    }
    private static byte[] normalBlock(byte[] lzx) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.writeBytes(new byte[24]);      // final block: next size/hash are zero
        for (int p = 0; p < lzx.length; ) {
            int n = Math.min(0x8000, lzx.length - p);
            out.write(n >>> 8); out.write(n);
            out.write(lzx, p, n); p += n;
        }
        out.write(0); out.write(0);
        while ((out.size() & 15) != 0) out.write(0);
        return out.toByteArray();
    }
    private static byte[] sha1(byte[] bytes) throws Exception {
        return MessageDigest.getInstance("SHA-1").digest(bytes);
    }
    private static void section(byte[] image, int i, String name, int rva, int size, long flags) {
        int p = 0x80 + 24 + 224 + i*40;
        str(image, p, name); le(image, p+8, size); le(image, p+12, rva);
        le(image, p+16, size); le(image, p+20, rva); le(image, p+36, flags);
    }
    static byte[] image() {
        byte[] a = new byte[65536];
        a[0]='M';a[1]='Z';le(a,0x3c,0x80);le(a,0x80,0x4550);
        le16(a,0x84,0x1f2);le16(a,0x86,4);le16(a,0x94,224);
        int o=0x98;le16(a,o,0x10b);le(a,o+16,0x1000);le(a,o+28,0x82000000L);
        le(a,o+56,0x20000);le(a,o+60,0x400);
        section(a,0,".text",0x1000,32,0x60000020L);
        section(a,1,".pdata",0x2000,8,0x40000040L);
        section(a,2,".data",0x3000,64,0xc0000040L);
        section(a,3,".reloc",0xfff0,48,0x42000040L);
        be(a,0x1000,0x4e800020L);be(a,0x1010,0x0100005a);
        be(a,0x2000,0x82001000L);be(a,0x2004,0x00000102);
        be(a,0x3000,0x0000005a);be(a,0x3004,0x0000005b);
        for(int i=0;i<16;i++)a[0xfff0+i]=(byte)(i+1);
        return a;
    }
    static byte[] fixture(int compression, String kind) throws Exception {
        byte[] image = image();
        byte[] plain;
        byte[] firstNormalHash = null;
        if (compression == 1) {
            plain = new byte[0xf000];
            System.arraycopy(image,0,plain,0,0x4000);
            System.arraycopy(image,0x5000,plain,0x4000,0xb000);
        }
        else if (compression == 2) {
            plain = normalBlock(lzxUncompressed(image));
            firstNormalHash = sha1(plain);
        }
        else plain=image;
        byte[] payload = kind.equals("none") ? plain : crypt(SESSION,plain);
        byte[] file = new byte[PAYLOAD+payload.length];
        str(file,0,"XEX2");be(file,4,1);be(file,8,PAYLOAD);be(file,16,SECURITY);be(file,20,4);
        optional(file,0,0x00010100,0x82001000L);optional(file,1,0x00010201,0x82000000L);
        optional(file,2,0x000003ff,FORMAT);optional(file,3,0x000103ff,IMPORTS);
        be(file,SECURITY,0x19c);be(file,SECURITY+4,image.length);be(file,SECURITY+0x110,0x82000000L);
        be(file,SECURITY+0x180,1);be(file,SECURITY+0x184,0x11);
        if (!kind.equals("none")) {
            byte[] key = crypt(kind.equals("retail") ? RETAIL : new byte[16],SESSION);
            System.arraycopy(key,0,file,SECURITY+0x150,16);
        }
        be(file,FORMAT,compression==1?24:compression==2?36:8);
        be16(file,FORMAT+4,kind.equals("none")?0:1);be16(file,FORMAT+6,compression);
        if(compression==1){be(file,FORMAT+8,0x4000);be(file,FORMAT+12,0x1000);be(file,FORMAT+16,0xb000);}
        if(compression==2){
            be(file,FORMAT+8,0x8000);be(file,FORMAT+12,plain.length);
            System.arraycopy(firstNormalHash,0,file,FORMAT+16,20);
        }
        be(file,IMPORTS,120);be(file,IMPORTS+4,16);be(file,IMPORTS+8,2);
        str(file,IMPORTS+12,"xam.xex");str(file,IMPORTS+20,"xam.xex");
        int lib=IMPORTS+28;be(file,lib,48);be(file,lib+28,0x20002400);
        be16(file,lib+36,0);be16(file,lib+38,2);
        be(file,lib+40,0x82003000L);be(file,lib+44,0x82001010L);
        lib+=48;be(file,lib,44);be(file,lib+28,0x20002401);be16(file,lib+36,1);be16(file,lib+38,1);
        be(file,lib+40,0x82003004L);
        System.arraycopy(payload,0,file,PAYLOAD,payload.length);
        return file;
    }
    private static byte[] xex0Fixture() {
        byte[] raw = image();
        int reloc = 0x80 + 24 + 224 + 3 * 40;
        le(raw, reloc + 16, 16); // raw PE stores only the available prefix; VirtualSize remains 48
        int payload = 0x1000;
        byte[] file = new byte[payload + raw.length];
        str(file, 0, "XEX0");
        be(file, 4, payload);
        be(file, 8, 0x81fff000L);
        be(file, 12, 0x21000);
        be(file, 16, 0);
        System.arraycopy(raw, 0, file, payload, raw.length);
        return file;
    }

    private static byte[] xex1Fixture() throws Exception {
        byte[] file = fixture(1, "devkit");
        file[3] = '1';
        Arrays.fill(file, SECURITY, FORMAT, (byte)0);
        be(file, SECURITY, 0x180);
        be(file, SECURITY + 4, image().length);
        be(file, SECURITY + 0x130, 0x82000000L);
        byte[] key = crypt(new byte[16], SESSION);
        System.arraycopy(key, 0, file, SECURITY + 0x134, 16);
        be(file, SECURITY + 0x158, 0);
        be(file, SECURITY + 0x164, 1);
        be(file, SECURITY + 0x168, 0x11);
        return file;
    }

    private static void check(boolean condition,String name) {
        if(!condition)throw new AssertionError(name); checks++;System.out.println("PASS "+name);
    }
    private static void reject(byte[] file,String expected) throws Exception {
        try {XexImage.parse(file);throw new AssertionError("Accepted malformed fixture: "+expected);}
        catch(IOException ex){check(ex.getMessage().contains(expected),"reject "+expected);}
    }
    public static void main(String[] args) throws Exception {
        for(int compression=0;compression<=2;compression++)for(String key:List.of("none","retail","devkit")) {
            XexImage x=XexImage.parse(fixture(compression,key));
            check(Arrays.equals(x.image,image()),"image equality "+compression+" "+key);
            check(x.keyKind.equals(key),"key selection "+compression+" "+key);
        }
        XexImage x=XexImage.parse(fixture(1,"retail"));
        check(x.sections.size()==4 && x.entryPoint==0x82001000L,"PE sections and entry");
        XexImage normal=XexImage.parse(fixture(2,"retail"));
        check(normal.normalWindowSize==0x8000 && normal.normalBlockCount==1
            && normal.normalLzxBytes>image().length && normal.normalTrailingBytes==0,
            "NORMAL metadata and deblocking");
        check(x.pdata.size()==1 && x.pdata.get(0).entry()==0x82001000L,"pdata seed");
        check(x.libraries.size()==2 && x.libraries.get(0).name().equals(x.libraries.get(1).name()),"duplicate library groups retained");
        check(x.libraries.get(0).records().get(1).kind()==1 && x.libraries.get(0).records().get(0).ordinal()==90,"import record decoding");
        var reloc=x.sections.get(3);byte[] rb=x.sectionBytes(reloc);
        check(reloc.availableBytes()==16 && reloc.syntheticTailBytes()==32,"cross-boundary section accounting");
        check(rb[0]==1 && rb[15]==16 && rb[16]==0 && rb[47]==0,"preserve prefix and zero synthetic tail");
        check(x.executable(0x82001000L,4) && !x.executable(0x82003000L,4),"executable seed validation");

        XexImage xex0 = XexImage.parse(xex0Fixture());
        check(xex0.containerMagic.equals("XEX0") && xex0.keyKind.equals("none")
            && xex0.encryption == 0 && xex0.compression == 0
            && xex0.imageBase == 0x81fff000L && xex0.entryPoint == 0x82000000L,
            "XEX0 raw PE normalization");

        XexImage xex1 = XexImage.parse(xex1Fixture());
        check(xex1.containerMagic.equals("XEX1") && xex1.keyKind.equals("devkit")
            && xex1.compression == 1, "XEX1 security normalization");

        byte[] early = fixture(0, "none");
        le(early, PAYLOAD + 0x98 + 28, 0x00400000);
        XexImage earlyParsed = XexImage.parse(early);
        check(earlyParsed.peImageBase == 0x00400000L && earlyParsed.imageBase == 0x82000000L
            && earlyParsed.warnings.stream().anyMatch(w -> w.contains("preferred ImageBase")),
            "early XEX2 preferred PE base");

        byte[] duplicate = fixture(1, "none");
        int duplicateName = PAYLOAD + 0x178 + 3 * 40;
        Arrays.fill(duplicate, duplicateName, duplicateName + 8, (byte)0);
        str(duplicate, duplicateName, ".text");
        XexImage duplicateParsed = XexImage.parse(duplicate);
        check(duplicateParsed.sections.get(3).peName().equals(".text")
            && duplicateParsed.sections.get(3).name().equals(".text#2"),
            "duplicate PE section names uniquely mapped");

        byte[] b=fixture(1,"none");b[0]=0;reject(b,"signature");
        reject(new byte[10],"Expected XEX0");
        b=fixture(1,"none");be(b,20,65536);reject(b,"header count");
        b=fixture(1,"none");be(b,4,0x40);reject(b,"patch modules");
        b=fixture(1,"none");be16(b,FORMAT+6,3);reject(b,"Unsupported compression");
        b=fixture(2,"none");b[FORMAT+16]^=1;reject(b,"SHA-1 mismatch");
        b=fixture(2,"none");be(b,FORMAT+8,0x4000);reject(b,"Invalid NORMAL/LZX window");
        b=fixture(2,"none");be(b,FORMAT+12,23);reject(b,"first block size");
        b=fixture(1,"none");be16(b,FORMAT+4,2);reject(b,"Unsupported encryption");
        b=fixture(1,"none");be(b,FORMAT+8,0x4001);reject(b,"expansion");
        b=fixture(1,"none");be(b,SECURITY+0x184,0x21);reject(b,"Descriptor size");
        b=fixture(1,"none");be(b,FORMAT,7);reject(b,"file-format");
        b=fixture(1,"none");be(b,24+8,0x00010100);reject(b,"Duplicate optional");
        b=fixture(1,"none");be16(b,IMPORTS+28+36,99);reject(b,"name index");
        b=fixture(1,"none");be(b,IMPORTS+28+40,0x83000000L);reject(b,"outside section");
        b=fixture(1,"none");le16(b,PAYLOAD+0x84,0x8664);reject(b,"machine");
        b=fixture(1,"none");le16(b,PAYLOAD+0x98,0x20b);reject(b,"PE32");
        b=fixture(1,"none");le(b,PAYLOAD+0x98+16,0x3000);reject(b,"entry points differ");
        b=fixture(1,"none");le(b,PAYLOAD+0x178+40+12,0x1010);reject(b,"Overlapping");
        b=fixture(1,"none");le(b,PAYLOAD+0x178+3*40+8,0x40000000);reject(b,"outside bounds");
        check(Arrays.equals(XexImage.parse(fixture(1,"none")).image, XexImage.parse(fixture(1,"none")).image),"repeat runs independent");
        var eofBits = new XenonLzxDecoder.BitBuffer(new byte[0]);
        eofBits.ensureBits(16);
        check(eofBits.peekBits(16)==0,"LZX bounded EOF lookahead");
        eofBits.removeBits(16);
        try {
            eofBits.ensureBits(16);
            throw new AssertionError("Accepted more than two synthetic EOF bytes");
        }
        catch(IOException ex) {
            check(ex.getMessage().contains("Truncated LZX bitstream"),"reject excess LZX EOF padding");
        }
        System.out.println("XEX_IMAGE_SELF_TEST_PASS checks="+checks);
    }
}
