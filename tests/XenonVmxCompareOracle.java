import java.nio.*;
import java.util.*;
/** Independent guest-byte oracle: NXP ALTIVECPEM Rev.3 p6-56; Xenon-specific
 * encoding/mapping cross-checked against Xenia 121bf93c VX128_R and emitter.
 * Equality is integer bit equality, including bit patterns that encode FP NaNs.
 */
public final class XenonVmxCompareOracle {
    private XenonVmxCompareOracle(){}
    public static byte[] vector(byte[] a,byte[] b){
        if(a.length!=16||b.length!=16)throw new IllegalArgumentException();
        byte[] r=new byte[16];
        for(int lane=0;lane<4;lane++){
            boolean equal=true;for(int j=0;j<4;j++)if(a[lane*4+j]!=b[lane*4+j])equal=false;
            Arrays.fill(r,lane*4,lane*4+4,equal?(byte)255:0);
        }
        return r;
    }
    public static int cr6(byte[] result){
        int trueBytes=0;for(byte x:result)if(x==(byte)255)trueBytes++;
        if(trueBytes==16)return 8;if(trueBytes==0)return 2;return 0;
    }
    public static int encoding(boolean record,int d,int a,int b){
        return 0x18000200|(record?0x40:0)|((d%32)<<21)|((a%32)<<16)|((b%32)<<11)|((d/32)<<2)|(a&32)|((a&64)<<4)|(b/32);
    }
    public static int[] registers(int w){return new int[]{((w>>>21)&31)|((w&12)<<3),((w>>>16)&31)|(w&32)|((w>>>4)&64),((w>>>11)&31)|((w&3)<<5)};}
    public static byte[] instruction(int w){return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(w).array();}
    public static String register(int n){return n<32?"vs"+(n+32):"v"+n;}
    public static byte[] operand(int k){
        int[] words={0,0x80000000,0x3f800000,0xbf800000,1,0x007fffff,0x00800000,0x7f7fffff,0x7f800000,0xff800000,0x7fc00001,0x7f800001,0xffffffff,0x7fffffff,0x80000001,0x01020304};
        var b=ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN);for(int i=0;i<4;i++)b.putInt(words[(k+i*3)%words.length]);return b.array();
    }
    public static byte[] peer(byte[] a,int mask){byte[] b=a.clone();for(int lane=0;lane<4;lane++)if((mask&(1<<lane))==0)b[lane*4+(lane%4)]^=(byte)(1<<lane);return b;}
}
