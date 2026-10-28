package xenon360.havok;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import xenon360.analysis.BinaryImage;

public final class HavokMetadataSelfTest {
    private static int checks;
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    private static void text(byte[] b, int at, String text) {
        byte[] s = text.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(s, 0, b, at, s.length);
    }
    public static void main(String[] args) throws Exception {
        staticInitializers();
        classDescriptors();
        for (int width : new int[] {4, 8}) for (boolean big : new boolean[] {false, true}) {
            byte[] data = new byte[1024], code = new byte[256];
            ByteBuffer words = ByteBuffer.wrap(data).order(big ? ByteOrder.BIG_ENDIAN : ByteOrder.LITTLE_ENDIAN);
            text(data, 0x100, "hkExample"); text(data, 0x120, "!hkExample");
            text(data, 0x140, "hk_2012.2.0-r1");
            long[] values = {0x1100, 0x1120, 0x2000, 0x2040, 0x1180, 32};
            for (int i=0;i<values.length;i++) {
                if (width==4) words.putInt(i*width, (int)values[i]);
                else words.putLong(i*width, values[i]);
            }
            if (width==4) words.putInt(0x180,0x2080); else words.putLong(0x180,0x2080);
            BinaryImage image = new BinaryImage(List.of(new BinaryImage.Segment(0x1000,data,false),
                new BinaryImage.Segment(0x2000,code,true)),width,big,width==4&&big);
            var found=HavokMetadata.scan(image,TaskMonitor.DUMMY);
            check(found.types().size()==1,"typed record width/endian");
            check(found.types().getFirst().objectSize()==32,"target size");
            check(found.versions().size()==1,"version marker");
            check(found.classes().isEmpty(),"typeinfo is not hkClass");
            // Valid-looking strings cannot validate a callback into data.
            if(width==4) words.putInt(3*width,0x1300); else words.putLong(3*width,0x1300);
            check(HavokMetadata.scan(image,TaskMonitor.DUMMY).types().isEmpty(),"reject data callback");
            if(width==4) words.putInt(3*width,0x2040); else words.putLong(3*width,0x2040);
            data[0x121]='x';
            check(HavokMetadata.scan(image,TaskMonitor.DUMMY).types().isEmpty(),"reject mismatched scoped name");
        }
        byte[] data = new byte[512], code = new byte[256];
        ByteBuffer d=ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN), c=ByteBuffer.wrap(code).order(ByteOrder.BIG_ENDIAN);
        text(data,0x100,"hkReferencedObject");
        d.putInt(0,0x1100).putInt(4,0x2000).putInt(8,0x2040).putInt(12,0x1180).putInt(0x180,0x2080);
        c.putInt(0,0x3d600000).putInt(4,0x394b1180).putInt(8,0x91430000).putInt(12,0x4e800020);
        BinaryImage legacy = new BinaryImage(List.of(new BinaryImage.Segment(0x1000,data,false),
            new BinaryImage.Segment(0x2000,code,true)),4,true,true);
        check(HavokMetadata.scan(legacy,TaskMonitor.DUMMY).types().size()==1,"legacy vtable write corroboration");
        c.putInt(8,0x91430004);
        check(HavokMetadata.scan(legacy,TaskMonitor.DUMMY).types().isEmpty(),"member store is not vptr");
        c.putInt(8,0x91430000); c.putInt(4,0x394b1184);
        check(HavokMetadata.scan(legacy,TaskMonitor.DUMMY).types().isEmpty(),"wrong vtable rejected");
        TaskMonitorAdapter cancelled = new TaskMonitorAdapter(true); cancelled.cancel();
        boolean caught=false;
        try { HavokMetadata.scan(legacy,cancelled); } catch(CancelledException expected) {caught=true;}
        check(caught,"cancellation");
        check(HavokMetadata.snake("hkpRigidBody").equals("hkp_rigid_body"),"one snake case name");
        check(legacy.segment(Long.MAX_VALUE,4)==null,"overflow bounded");
        System.out.println("XENON_HAVOK_SELF_TEST_PASS checks="+checks);
    }
    private static void staticInitializers() throws Exception {
        byte[] code=new byte[1024],data=new byte[512];
        ByteBuffer c=ByteBuffer.wrap(code).order(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer d=ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        text(data,0,"hkReferencedObject");d.putLong(0x100,0x1240);
        put(code,0,"4883ec28e800000000488d0d000000004889050000000048890d00000000488d0d0000000048890d00000000488d0d0000000048890d000000004883c428c3");
        relative(c,4,1,5,0x1100);relative(c,9,3,7,0x2000);relative(c,16,3,7,0x3018);
        relative(c,23,3,7,0x3000);relative(c,30,3,7,0x1200);relative(c,37,3,7,0x3008);
        relative(c,44,3,7,0x1240);relative(c,51,3,7,0x3010);
        put(code,0x100,"4883ec38488d4c2420e800000000488b4424204883c438c3");relative(c,0x109,1,5,0x1180);
        put(code,0x180,"488d0500000000488901488bc1c3");relative(c,0x180,3,7,0x2100);
        put(code,0x200,"4885c90f8500000000c3");relative(c,0x200,5,9,0x1180);
        put(code,0x240,"488b0133d248ff20");
        var image=new BinaryImage(List.of(new BinaryImage.Segment(0x1000,code,true),new BinaryImage.Segment(0x2000,data,false)),
            List.of(new BinaryImage.Mapping(0x1000,1024),new BinaryImage.Mapping(0x2000,512),new BinaryImage.Mapping(0x3000,32)),8,false,false);
        var found=HavokMetadata.scan(image,TaskMonitor.DUMMY);
        check(found.types().size()==1,"static initializer relational proof");
        check(found.types().getFirst().address()==0x3000 && found.types().getFirst().vtable()==0x2100,"static initializer addresses");
        for(int offset:new int[]{19,26,40,54,0x10a,0x183,0x205,0x247}) {
            byte saved=code[offset];code[offset]^=1;
            check(HavokMetadata.scan(image,TaskMonitor.DUMMY).types().isEmpty(),"reject broken initializer relation "+offset);
            code[offset]=saved;
        }
        var unmapped=new BinaryImage(image.segments,8,false,false);
        check(HavokMetadata.scan(unmapped,TaskMonitor.DUMMY).types().isEmpty(),"reject writes outside mapped image");
    }
    private static void put(byte[] bytes,int offset,String hex) {
        byte[] value=HexFormat.of().parseHex(hex);System.arraycopy(value,0,bytes,offset,value.length);
    }
    private static void classDescriptors() throws Exception {
        byte[] data=new byte[1024];var d=ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        text(data,0x200,"hkFixtureBase");text(data,0x220,"hkFixtureChild");text(data,0x240,"value");
        d.putInt(0,0x1200).putInt(8,16).putInt(24,0x1100).putInt(28,1);
        d.putInt(0x40,0x1220).putInt(0x44,0x1000).putInt(0x48,32).putInt(0x58,0x1120).putInt(0x5c,1);
        for(int at:new int[]{0x100,0x120})d.putInt(at,0x1240).put(at+12,(byte)8).putShort(at+18,(short)4);
        var image=new BinaryImage(List.of(new BinaryImage.Segment(0x1000,data,false)),4,true,true);
        var found=HavokMetadata.scan(image,TaskMonitor.DUMMY);
        check(found.classes().size()==2,"32-bit class hierarchy with bounded members");
        check(found.types().isEmpty(),"class descriptor is not typeinfo");
        check(found.classes().getFirst().members().getFirst().offset()==4,"member offset retained");
        d.putInt(4,0x1040);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().isEmpty(),"cyclic inheritance rejected");
        d.putInt(4,0);d.putShort(0x112,(short)16);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().isEmpty(),"out of object member and disconnected child rejected");
        d.putShort(0x112,(short)4);d.putInt(0x48,8);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().size()==1,"child smaller than parent rejected");
        d.putInt(0x48,32);d.putInt(0x44,0x1040);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().size()==1,"self parent rejected");
        d.putInt(0x44,0x1000);d.putInt(0x5c,513);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().size()==1,"oversized member table rejected");
        d.putInt(0x5c,1);d.putInt(0x58,0x5000);
        check(HavokMetadata.scan(image,TaskMonitor.DUMMY).classes().size()==1,"unmapped member table rejected");
    }
    private static void relative(ByteBuffer c,int offset,int disp,int length,int target) {
        c.putInt(offset+disp,target-(0x1000+offset+length));
    }
}
