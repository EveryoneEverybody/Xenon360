import java.nio.*;
import java.util.*;

/** Independent guest-order byte-array oracle and deterministic test inputs.
 * No SLEIGH expressions, emulator callbacks, or host vector shuffles. */
public final class XenonVmxPermuteOracle {
    private XenonVmxPermuteOracle() {}
    public static byte[] permute(byte[] a,byte[] b,byte[] c) {
        byte[] table=new byte[32],result=new byte[16];
        System.arraycopy(a,0,table,0,16);System.arraycopy(b,0,table,16,16);
        for(int i=0;i<16;i++)result[i]=table[c[i]&31];
        return result;
    }
    public static String vr(int r){return r<32?"vs"+(r+32):"v"+r;}
    public static int encoding(int d,int a,int b,int c){
        if(c<0||c>7)throw new IllegalArgumentException("C must be v0..v7");
        return 0x14000000|(d&31)<<21|(a&31)<<16|(b&31)<<11|
            (d>>>5)<<2|(a&32)|((a&64)<<4)|(b>>>5)|c<<6;
    }
    public static int memory(int operation,int v,int r){return 4<<26|(v&31)<<21|r<<11|operation<<6|(v>>>5)<<2|3;}
    public static byte[] word(int n){return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(n).array();}
    public static byte[] pattern(int p,int source){
        byte[] r=new byte[16];Random random=new Random(0x5e1ec70L+997L*p+71L*source);
        for(int i=0;i<16;i++)r[i]=switch(p){
            case 0 -> (byte)(i+16*source);
            case 1 -> (byte)(0x80+i*3+source*53);
            case 2 -> (byte)(source==0?0:255);
            case 3 -> (byte)(source==0?255:0);
            case 4 -> (byte)((i%2==0?0xaa:0x55)^(source*0x33));
            default -> (byte)random.nextInt(256);
        };return r;
    }
    public static byte[] control(int kind){
        byte[] r=new byte[16];
        for(int i=0;i<16;i++)r[i]=(byte)switch(kind){
            case 0 -> i; case 1 -> 15-i; case 2 -> 16+i; case 3 -> 31-i;
            case 4 -> 15; case 5 -> 16;
            case 6 -> i%2==0?i/2:16+i/2;
            case 7 -> ((i/4)%2)*16+(i/8)*4+i%4;
            default -> (i*29+0x83)&255;
        };return r;
    }
    public static List<int[]> partitions(){
        List<int[]> out=new ArrayList<>();
        // Restricted growth strings enumerate all 15 equality partitions of D,A,B,C.
        for(int a=0;a<=1;a++)for(int b=0;b<=Math.max(0,a)+1;b++)
            for(int c=0;c<=Math.max(a,b)+1;c++)out.add(new int[]{0,a,b,c});
        return out;
    }
    public static int[] realize(int[] p,int c){
        int[] map=new int[4];int next=32+c;
        for(int i=0;i<4;i++){if(i==p[3])map[i]=c;else{map[i]=next;next+=32;}}
        int[] r=new int[4];for(int i=0;i<4;i++)r[i]=map[p[i]];return r;
    }
    public static String partition(int d,int a,int b,int c){
        Map<Integer,Integer> ids=new LinkedHashMap<>();StringBuilder s=new StringBuilder();
        for(int x:new int[]{d,a,b,c}){ids.putIfAbsent(x,ids.size());s.append(ids.get(x));}return s.toString();
    }
    public static byte[][] effective(int a,int b,int c,byte[] av,byte[] bv,byte[] cv){
        Map<Integer,byte[]> registers=new HashMap<>();
        registers.put(a,av);registers.put(b,bv);registers.put(c,cv);
        return new byte[][]{registers.get(a),registers.get(b),registers.get(c)};
    }
}
