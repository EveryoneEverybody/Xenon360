package xenon360.havok;

import java.util.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.BinaryImage;

/** A narrowly validated x64 static initializer, not a reconstruction of runtime memory.
 * All four descriptor writes, the vtable getter, constructor and both callbacks must agree.
 * Unsupported compiler forms are deliberately withheld. No PC ABI is transferred to Xenon.
 */
final class HavokStaticInitializers {
    private HavokStaticInitializers() {}
    private static boolean bytes(BinaryImage m,long at,int... values) {
        for(int i=0;i<values.length;i++) if(m.unsigned(at+i,1)!=values[i])return false;
        return true;
    }
    private static long rip(BinaryImage m,long at,int displacement,int length) {
        return at+length+(int)m.unsigned(at+displacement,4);
    }
    static List<HavokMetadata.TypeInfo> scan(BinaryImage m,Map<Long,String> names,TaskMonitor monitor)
            throws CancelledException {
        List<HavokMetadata.TypeInfo> result=new ArrayList<>();Set<Long> slots=new HashSet<>();
        for(var s:m.segments) {
            if(!s.executable())continue;
            for(int offset=0;offset+63<=s.bytes().length;offset++) {
                if((offset&4095)==0)monitor.checkCancelled();
                if((s.bytes()[offset]&255)!=0x48)continue;
                long a=s.address()+offset;
                if(!bytes(m,a,0x48,0x83,0xec,0x28,0xe8) ||
                    !bytes(m,a+9,0x48,0x8d,0x0d) || !bytes(m,a+16,0x48,0x89,0x05) ||
                    !bytes(m,a+23,0x48,0x89,0x0d) || !bytes(m,a+30,0x48,0x8d,0x0d) ||
                    !bytes(m,a+37,0x48,0x89,0x0d) || !bytes(m,a+44,0x48,0x8d,0x0d) ||
                    !bytes(m,a+51,0x48,0x89,0x0d) || !bytes(m,a+58,0x48,0x83,0xc4,0x28,0xc3))continue;
                String name=names.get(rip(m,a+9,3,7));if(name==null)continue;
                long slot=rip(m,a+23,3,7),finish=rip(m,a+30,3,7),cleanup=rip(m,a+44,3,7);
                if((slot&7)!=0 || !m.mapped(slot,32) || rip(m,a+16,3,7)!=slot+24 ||
                    rip(m,a+37,3,7)!=slot+8 || rip(m,a+51,3,7)!=slot+16 ||
                    !m.executable(finish) || !m.executable(cleanup))continue;
                long getter=rip(m,a+4,1,5);
                if(!m.executable(getter) || !bytes(m,getter,0x48,0x83,0xec,0x38,0x48,0x8d,0x4c,0x24,0x20,0xe8) ||
                    !bytes(m,getter+14,0x48,0x8b,0x44,0x24,0x20,0x48,0x83,0xc4,0x38,0xc3))continue;
                long constructor=rip(m,getter+9,1,5);
                if(!m.executable(constructor) || !bytes(m,constructor,0x48,0x8d,0x05) ||
                    !bytes(m,constructor+7,0x48,0x89,0x01,0x48,0x8b,0xc1,0xc3))continue;
                long vtable=rip(m,constructor,3,7);
                var table=m.segment(vtable,8);
                if((vtable&7)!=0 || table==null || table.executable() || !m.executable(m.pointer(vtable)))continue;
                if(!bytes(m,finish,0x48,0x85,0xc9,0x0f,0x85) || m.unsigned(finish+9,1)!=0xc3 ||
                    rip(m,finish,5,9)!=constructor || !bytes(m,cleanup,0x48,0x8b,0x01,0x33,0xd2,0x48,0xff,0x20))continue;
                if(!slots.add(slot))continue;
                result.add(new HavokMetadata.TypeInfo(slot,name,"hk_type_info_four_pointer_x64_initializer",finish,cleanup,vtable,-1,
                    List.of("static initializer "+BinaryImage.address(a)+" writes four contiguous mapped pointer slots",
                        "vtable getter "+BinaryImage.address(getter)+" constructs a stack object and reads its vptr",
                        "constructor "+BinaryImage.address(constructor)+" writes the independently executable vtable",
                        "finish callback conditionally branches to that same constructor",
                        "cleanup callback dispatches through vtable slot zero; object size is unknown")));
                if(result.size()>=10000)return result;
            }
        }
        return result;
    }
}
