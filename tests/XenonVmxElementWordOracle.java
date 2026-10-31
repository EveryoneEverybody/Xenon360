import java.math.BigInteger;
import java.nio.*;
import java.util.*;

/** Independent architectural oracle: guest byte arrays and integer address arithmetic.
 * NXP ALTIVECPEM Rev.3 section stvewx (6-27); Xenia 121bf93c, VX128_1 mapping.
 * This does not interpret the candidate's shifts or use a userop callback. */
public final class XenonVmxElementWordOracle {
    private XenonVmxElementWordOracle() {}
    public static final BigInteger U64=BigInteger.ONE.shiftLeft(64), U32=BigInteger.ONE.shiftLeft(32);
    public record Result(BigInteger raw64,long effective32,long storeAddress,int wordIndex,byte[] bytes,long value) {}
    public static BigInteger unsigned(long value){return new BigInteger(Long.toUnsignedString(value));}
    public static Result reference(int ra,int rb,long[] gprs,byte[] guestVector){
        if(guestVector.length!=16)throw new IllegalArgumentException("128-bit vector required");
        BigInteger sum=(ra==0?BigInteger.ZERO:unsigned(gprs[ra])).add(unsigned(gprs[rb]));
        long ea=sum.mod(U32).longValueExact();
        long aligned=(ea/4)*4;
        int word=(int)((ea%16)/4);
        byte[] bytes=Arrays.copyOfRange(guestVector,word*4,word*4+4);
        long value=0;for(byte b:bytes)value=value*256+Byte.toUnsignedInt(b);
        return new Result(sum.mod(U64),ea,aligned,word,bytes,value);
    }
    public static int encoding(int vector,int ra,int rb){
        if(vector<0||vector>127||ra<0||ra>31||rb<0||rb>31)throw new IllegalArgumentException();
        return 0x10000183|((vector%32)<<21)|(ra<<16)|(rb<<11)|((vector/32)<<2);
    }
    public static int vectorMemory(int operation,int vector,int rb){return 0x10000003|((vector%32)<<21)|(rb<<11)|(operation<<6)|((vector/32)<<2);}
    public static String register(int v){return v<32?"vs"+(v+32):"v"+v;}
    public static byte[] instruction(int word){return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(word).array();}
    public static byte[] pattern(int kind,int salt){
        byte[] bytes=new byte[16];Random rng=new Random(0x535457455758L+kind*131L+salt*997L);
        for(int i=0;i<16;i++)bytes[i]=switch(kind){
            case 0 -> (byte)(0x13+i*11);case 1 -> (byte)0;case 2 -> (byte)255;
            case 3 -> (byte)(0x80+(i*7)%128);case 4 -> (byte)(i%2==0?0xaa:0x55);
            default -> (byte)rng.nextInt(256);
        };return bytes;
    }
}
