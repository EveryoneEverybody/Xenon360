import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import xenon360.XenonSwitchAnalyzer;
import xenon360.analysis.XenonEvidence;

public class XenonSwitchTest extends GhidraScript {
    private int checks;
    private void check(boolean ok,String what){checks++;if(!ok)throw new AssertionError(what);}
    @Override public void run() throws Exception {
        var imported=currentProgram;
        for(int variant=0;variant<11;variant++) {
            var p=new ProgramDB("Switch fixture "+variant,imported.getLanguage(),
                imported.getLanguage().getCompilerSpecByID(imported.getCompilerSpec().getCompilerSpecID()),this);
            currentProgram=p;
            try{scenario(variant);}finally{currentProgram=imported;p.release(this);}
        }
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("result","PASS","checks",checks,"fixtures",11));
        println("XENON_SWITCH_TEST_PASS checks="+checks);
    }
    private void scenario(int variant) throws Exception {
        var p=currentProgram;byte[] data=new byte[256],code=new byte[256];
        var words=ByteBuffer.wrap(code).order(ByteOrder.BIG_ENDIAN);
        int[] pattern={0x2b0b0001,0x4199005c,0x3d808400,0x398c0000,0x7c0c58ae,
            0x3d808400,0x60000000,0x398c1030,0x60000000,0x7d8c0214,0x7d8903a6,0x4e800420};
        data[1]=8;
        if(variant==1){pattern[5]=0x5400103a;pattern[6]=0x3d808400;pattern[7]=0x60000000;pattern[8]=0x398c1030;data[1]=2;}
        if(variant==3)pattern[0]=0x2b070001;
        if(variant==4)data[1]=3;
        for(int i=0;i<pattern.length;i++)words.putInt(i*4,pattern[i]);
        words.putInt(0x30,0x3860000b).putInt(0x34,0x4e800020);
        words.putInt(0x38,0x38600016).putInt(0x3c,0x4e800020);
        words.putInt(0x60,0x38600021).putInt(0x64,0x4e800020);
        var initial=new AddressSet(toAddr(0x84001000L),toAddr(0x8400102fL));initial.add(toAddr(0x84001060L),toAddr(0x84001067L));
        int tx=p.startTransaction("Fixture");
        try {
            var table=p.getMemory().createInitializedBlock("table",toAddr(0x84000000L),new java.io.ByteArrayInputStream(data),data.length,monitor,false);table.setWrite(variant==2);
            var text=p.getMemory().createInitializedBlock("text",toAddr(0x84001000L),new java.io.ByteArrayInputStream(code),code.length,monitor,false);text.setExecute(true);
            var dis=new DisassembleCommand(toAddr(0x84001000L),initial,true);dis.enableCodeAnalysis(false);dis.applyTo(p,monitor);
            p.getFunctionManager().createFunction(null,toAddr(0x84001000L),initial,SourceType.ANALYSIS);
            if(variant==5)getFunctionAt(toAddr(0x84001000L)).setName("user_switch",SourceType.USER_DEFINED);
            if(variant==6){var body=new AddressSet(toAddr(0x84001038L),toAddr(0x8400103fL));var cmd=new DisassembleCommand(toAddr(0x84001038L),body,true);cmd.enableCodeAnalysis(false);cmd.applyTo(p,monitor);p.getFunctionManager().createFunction("existing_case_owner",toAddr(0x84001038L),body,SourceType.USER_DEFINED);}
            if(variant==7)p.getListing().createData(toAddr(0x84001030L),DWordDataType.dataType);
            if(variant==9)p.getReferenceManager().addMemoryReference(toAddr(0x8400102cL),toAddr(0x84001060L),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,-1);
        }finally{p.endTransaction(tx,true);}
        var f=getFunctionAt(toAddr(0x84001000L));var before=new AddressSet(f.getBody());String name=f.getName();
        var analyzer=new XenonSwitchAnalyzer();var log=new MessageLog();
        TaskMonitor taskMonitor=monitor;
        if(variant==8)taskMonitor=new TaskMonitorAdapter(true){@Override public void checkCancelled() throws CancelledException {
            if(f.getBody().contains(toAddr(0x84001030L)))throw new CancelledException();super.checkCancelled();}};
        boolean cancelled=false,ok=false;
        try{ok=analyzer.added(p,variant==10?new AddressSet(toAddr(0x84001000L)):p.getMemory(),taskMonitor,log);}
        catch(CancelledException ex){cancelled=true;}
        if(variant<2) {
            check(ok,"valid table accepted");check(f.getBody().contains(toAddr(0x84001030L),toAddr(0x8400103fL)),"both case bodies recovered");
            check(Arrays.stream(getInstructionAt(toAddr(0x8400102cL)).getReferencesFrom()).filter(r->r.getReferenceType().isJump()).count()==2,"two exact case edges");
            var recovered=new AddressSet(f.getBody());check(analyzer.added(p,p.getMemory(),monitor,log),"repeat succeeds");check(recovered.equals(f.getBody()),"repeat preserves body");
        }else {
            check(before.equals(f.getBody()),"unsafe/partial/cancelled fixture preserved "+variant);
            check((variant==8)==cancelled,"cancellation contract "+variant);
            if(variant==8)check(getInstructionAt(toAddr(0x84001030L))==null,"cancel rolls back disassembly");
        }
        check(f.getName().equals(name),"function name preserved "+variant);
    }
}
