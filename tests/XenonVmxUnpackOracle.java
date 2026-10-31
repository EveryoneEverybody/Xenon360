import java.nio.*;
import java.util.*;

/** Guest-byte mathematical specification, independent of SLEIGH subpieces.
 * NXP ALTIVECPEM Rev.3 vupkhsh/vupklsh, printed pages 6-173 and 6-176.
 * Xenon encoding: Xenia 121bf93c and powerpc-rs 4643ee0f, isa.yaml.
 */
public final class XenonVmxUnpackOracle {
    private XenonVmxUnpackOracle() {}
    public static byte[] reference(boolean low,byte[] source) {
        if(source.length!=16)throw new IllegalArgumentException("128-bit source");
        ByteBuffer result=ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);
        int first=low?8:0;
        for(int i=first;i<first+8;i+=2) {
            int unsigned=Byte.toUnsignedInt(source[i])*256+Byte.toUnsignedInt(source[i+1]);
            int signed=unsigned<32768?unsigned:unsigned-65536;
            result.putInt(signed);
        }
        return result.array();
    }
    public static int encoding(boolean low,int d,int b) {
        if(d<0||d>127||b<0||b>127)throw new IllegalArgumentException();
        return (low?0x180007e0:0x180007a0)|((d%32)<<21)|((b%32)<<11)|((d/32)<<2)|(b/32);
    }
    public static String register(int r){return r<32?"vs"+(r+32):"v"+r;}
    public static byte[] instruction(int w){return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(w).array();}
    public static byte[] pattern(int kind,int salt) {
        String[] directed={
            "00000000000000000000000000000000","ffffffffffffffffffffffffffffffff",
            "000100027fff80008001fffeffff0000","80007fff0001ffff7ffe80010000fffe",
            "aaaa5555aa5555aacccc3333cc3333cc","0123456789abcdef76543210fedcba98",
            "00010203040506078081828384858687","7fff80007ffe80010001ffff0000fffe"
        };
        if(kind<directed.length)return HexFormat.of().parseHex(directed[kind]);
        byte[] value=new byte[16];new Random(0x55355041434bL+kind*101L+salt*997L).nextBytes(value);return value;
    }
}
