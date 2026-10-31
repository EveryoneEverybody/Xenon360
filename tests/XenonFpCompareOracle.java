/** Independent binary64 classification/order oracle; never reads SLEIGH or p-code. */
public final class XenonFpCompareOracle {
    private XenonFpCompareOracle() {}
    public static final long[] VALUES={0L,0x8000000000000000L,1L,0x8000000000000001L,
        0x000fffffffffffffL,0x800fffffffffffffL,0x0010000000000000L,0x8010000000000000L,
        0x3fefffffffffffffL,0x3ff0000000000000L,0x3ff0000000000001L,0xbff0000000000000L,
        0x3ff0000010000000L,0x3ff000000fffffffL,0x3ff0000010000001L,
        0x7fefffffffffffffL,0xffefffffffffffffL,0x7ff0000000000000L,0xfff0000000000000L,
        0x7ff8000000000000L,0xfff8000000000123L,0x7ff0000000000001L,0xfff0000000000123L};
    public static boolean nan(long x){return (x&0x7ff0000000000000L)==0x7ff0000000000000L&&(x&0xfffffffffffffL)!=0;}
    public static String kind(long x){return nan(x)?((x&0x8000000000000L)!=0?"quiet_nan":"signaling_nan"):(x&0x7fffffffffffffffL)==0?"zero":(x&0x7ff0000000000000L)==0?"subnormal":(x&0x7fffffffffffffffL)==0x7ff0000000000000L?"infinity":"normal";}
    public static int condition(long a,long b){
        if(nan(a)||nan(b))return 1;
        if(a==b||((a|b)&0x7fffffffffffffffL)==0)return 2;
        boolean less;
        if((a<0)!=(b<0))less=a<0;
        else {int c=Long.compareUnsigned(a&Long.MAX_VALUE,b&Long.MAX_VALUE);less=a<0?c>0:c<0;}
        return less?8:4;
    }
    public static int word(int cr,int a,int b){return 0xfc000000|(cr<<23)|(a<<16)|(b<<11);}
    public static byte[] bytes(int w){return java.nio.ByteBuffer.allocate(4).putInt(w).array();}
    public static java.math.BigInteger bits(long x){return new java.math.BigInteger(Long.toUnsignedString(x));}
}
