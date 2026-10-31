import java.nio.*;
import java.nio.file.*;
import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.XenonEvidence;

/** A native splat must preserve the source LOAD -> stored-value dependency after
 * decompilation, not just in raw p-code. Synthetic lvlx/splat/stvx/blr functions.
 */
public class XenonVmxSplatDecompilerTest extends GhidraScript {
    private int checks,cases;
    private void check(boolean ok,String s){checks++;if(!ok)throw new AssertionError(s);}
    private int memory(int operation,int v,int r){return 4<<26|(v&31)<<21|r<<11|operation<<6|(v>>>5)<<2|3;}
    private boolean reachesStore(Varnode seed){
        var todo=new ArrayDeque<Varnode>();todo.add(seed);
        Set<Varnode> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        while(!todo.isEmpty()){
            Varnode v=todo.removeFirst();if(!seen.add(v))continue;
            var it=v.getDescendants();
            while(it.hasNext()){
                PcodeOp op=it.next();
                if(op.getOpcode()==PcodeOp.STORE&&op.getInput(2)==v)return true;
                if(op.getOutput()!=null&&op.getOpcode()!=PcodeOp.CALLOTHER)todo.add(op.getOutput());
            }
        }
        return false;
    }
    @Override protected void run()throws Exception{
        var language=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));Object owner=new Object();
        ProgramDB p=new ProgramDB("native-splat-decompiler-regression",language,language.getDefaultCompilerSpec(),owner);
        List<Object> results=new ArrayList<>();
        try{
            var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);
            int tx=p.startTransaction("create synthetic functions");
            try{
                p.getMemory().createInitializedBlock("code",start,0x10000,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);
                int index=0;
                for(int d:new int[]{0,31,32,63,64,95,96,127})for(int s:new int[]{d,(d+37)%128})for(int lane=0;lane<4;lane++){
                    var entry=start.add(index++*0x100);
                    int splat=0x18000730|(d&31)<<21|lane<<16|(s&31)<<11|(d>>>5)<<2|(s>>>5);
                    byte[] code=ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putInt(memory(16,s,4)).putInt(splat).putInt(memory(7,d,3)).putInt(0x4e800020).array();
                    p.getMemory().setBytes(entry,code);
                    check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(15)),true).applyTo(p,TaskMonitor.DUMMY),"fixture disassembly");
                    p.getFunctionManager().createFunction("splat_"+d+"_"+s+"_"+lane,entry,new AddressSet(entry,entry.add(15)),SourceType.USER_DEFINED);
                }
            }finally{p.endTransaction(tx,true);}
            DecompInterface decompiler=new DecompInterface();
            try{
                check(decompiler.openProgram(p),"decompiler opens fixture");
                var functions=p.getFunctionManager().getFunctions(true);
                while(functions.hasNext()){
                    var f=functions.next();var result=decompiler.decompileFunction(f,10,monitor);
                    check(result.decompileCompleted()&&result.getHighFunction()!=null,"completed "+f.getName()+": "+result.getErrorMessage());
                    boolean dependency=false;int loads=0,stores=0,opaque=0;
                    var ops=result.getHighFunction().getPcodeOps();
                    while(ops.hasNext()){
                        PcodeOp op=ops.next();
                        if(op.getOpcode()==PcodeOp.LOAD){loads++;dependency|=reachesStore(op.getOutput());}
                        if(op.getOpcode()==PcodeOp.STORE)stores++;
                        if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;
                    }
                    String c=result.getDecompiledFunction().getC();
                    var row=Map.of("function",f.getName(),"loads",loads,"stores",stores,"opaque",opaque,"load_reaches_stored_value",dependency,"c",c);
                    results.add(row);
                    if(!dependency||opaque!=0){
                        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("status","FAIL","checks",checks,"cases",results));
                        throw new AssertionError("decompiler must retain source memory dependency: "+f.getName());
                    }
                    check(dependency,"LOAD to STORE value path "+f.getName());check(opaque==0,"no opaque operations "+f.getName());cases++;
                }
            }finally{decompiler.dispose();}
            check(cases==64,"all bank/alias/selector functions");
            XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("status","PASS","checks",checks,"decompiler_cases",cases,"results",results));
            println("XENON_VMX_SPLAT_DECOMPILER_PASS checks="+checks+" cases="+cases);
        }finally{p.release(owner);}
    }
}
