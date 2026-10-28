import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import xenon360.XenonSwitchAnalyzer;
import xenon360.analysis.XenonEvidence;

/** Exact positive targets and failure atomicity, including nested dispatches. */
public class XenonHalfwordSwitchTest extends GhidraScript {
    private static final long CODE=0x84010000L,DATA=0x84000000L;
    private int checks;
    private void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private Address a(long x){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);}
    private int lis(int r,long x){return 0x3c000000|(r<<21)|((int)((x+0x8000)>>16)&65535);}
    private int addi(int r,long x){return 0x38000000|(r<<21)|(r<<16)|((int)x&65535);}
    private int[] dispatch(long table,long base,int count,int index,boolean nop,boolean shiftFirst) {
        int[] w={0x2b000000|(index<<16)|(count-1),0x419900bc,lis(12,table),addi(12,table),0x5400083c|(index<<21),0x7c0c022e,lis(12,base),addi(12,base),0x7d8c0214,0x7d8903a6,0x60000000,0x4e800420};
        if(shiftFirst){int x=w[4];w[4]=w[3];w[3]=w[2];w[2]=x;}
        if(!nop){w[10]=w[11];return Arrays.copyOf(w,11);}return w;
    }
    @Override protected void run() throws Exception {
        var original=currentProgram;
        String[] names={"source_form","upstream_form","index_r22","nested","existing_prefix","owned_targets","negative_low","called_wrapper","called_user_label","called_budget","writable_table","executable_table","wrong_guard","signed_guard","wrong_ctr","indirect_call","unaligned_target","unmapped_target","defined_data","other_owner","manual_name","user_label","conflicting_reference","interior_entry","nested_invalid","cancel_reference","cancel_body","partial_selection","budget","index_clobbered","odd_table"};
        for(String name:names) {
            var p=new ProgramDB(name,original.getLanguage(),original.getLanguage().getCompilerSpecByID(original.getCompilerSpec().getCompilerSpecID()),this);currentProgram=p;
            try{fixture(name);}finally{currentProgram=original;p.release(this);}
        }
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("result","PASS","checks",checks,"fixtures",names.length));
        println("XENON_HALFWORD_TEST_PASS checks="+checks);
    }
    private void fixture(String name) throws Exception {
        boolean positive=Set.of("source_form","upstream_form","index_r22","nested","existing_prefix","owned_targets","negative_low","called_wrapper").contains(name);
        boolean nested=name.equals("nested")||name.equals("nested_invalid");
        boolean upstream=name.equals("upstream_form");long branch=CODE+(upstream?40:44),base=branch+4;
        long dataAddress=DATA+(name.equals("negative_low")?0x8000:0)+(name.equals("odd_table")?1:0);
        byte[] bytes=new byte[name.equals("budget")?0x12000:0x2000],data=new byte[0x100];
        var code=ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);var table=ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int index=name.equals("index_r22")?22:name.equals("index_clobbered")?12:11;
        int[] words=dispatch(dataAddress,base,3,index,!upstream,upstream);
        if(name.equals("wrong_guard"))words[0]=0x2b070002;
        if(name.equals("signed_guard"))words[0]=0x2f0b0002;
        if(name.equals("wrong_ctr"))words[9]=0x7c6903a6;
        if(name.equals("indirect_call"))words[words.length-1]=0x4e800421;
        for(int n=0;n<words.length;n++)code.putInt(n*4,words[n]);
        for(int n=0;n<3;n++){int off=(int)(base-CODE)+n*8;code.putInt(off,0x38600010+n).putInt(off+4,0x4e800020);table.putShort(n*2,(short)(n*8));}
        code.putInt(0xc0,0x38600000).putInt(0xc4,0x4e800020);
        if(name.startsWith("called_")) {
            code.putInt((int)(base-CODE),0x48000001|(int)(CODE+0x200-base));
            int[] wrapper={0x7c0802a6,0x90010004,0x9421ffe0,0x480000f5,0x38210020,0x80010004,0x7c0803a6,0x4e800020};
            for(int n=0;n<wrapper.length;n++)code.putInt(0x200+n*4,wrapper[n]);
            code.putInt(0x300,0x38600023).putInt(0x304,0x4e800020);
            if(name.equals("called_budget")){for(int off=0x200;off<0x1300;off+=4)code.putInt(off,0x60000000);code.putInt(0x1300,0x4e800020);}
        }
        if(name.equals("unaligned_target"))table.putShort(4,(short)17);
        if(name.equals("unmapped_target"))table.putShort(4,(short)0x8000);
        if(nested) {
            table.putShort(4,(short)(CODE+0x100-base));int[] inner=dispatch(dataAddress+0x20,CODE+0x130,2,11,true,false);
            inner[1]=0x4199007c; // default at CODE+0x180
            for(int n=0;n<inner.length;n++)code.putInt(0x100+n*4,inner[n]);
            table.putShort(0x20,(short)0).putShort(0x22,(short)(name.equals("nested_invalid")?9:8));
            code.putInt(0x130,0x38600021).putInt(0x134,0x4e800020).putInt(0x138,0x38600022).putInt(0x13c,0x4e800020).putInt(0x180,0x4e800020);
        }
        if(name.equals("budget")) {
            for(int off=0x200;off<0x11000;off+=4)code.putInt(off,0x60000000);
            code.putInt(0x11000,0x4e800020);
            for(int n=0;n<3;n++)table.putShort(n*2,(short)(CODE+0x200+n*4-base));
        }
        var initial=new AddressSet(a(CODE),a(branch+3));initial.add(a(CODE+0xc0),a(CODE+0xc7));
        int tx=currentProgram.startTransaction("Fixture");
        try {
            var b=currentProgram.getMemory().createInitializedBlock("code",a(CODE),new java.io.ByteArrayInputStream(bytes),bytes.length,monitor,false);b.setExecute(true);
            b=currentProgram.getMemory().createInitializedBlock("table",a(dataAddress),new java.io.ByteArrayInputStream(data),data.length,monitor,false);b.setWrite(name.equals("writable_table"));b.setExecute(name.equals("executable_table"));
            var dis=new DisassembleCommand(a(CODE),initial,true);dis.enableCodeAnalysis(false);dis.applyTo(currentProgram,monitor);
            currentProgram.getFunctionManager().createFunction(null,a(CODE),initial,SourceType.ANALYSIS);
            if(name.equals("owned_targets")){var extra=new AddressSet(a(base),a(base+23));dis=new DisassembleCommand(a(base),extra,false);dis.enableCodeAnalysis(false);dis.applyTo(currentProgram,monitor);for(int n=1;n<6;n++){dis=new DisassembleCommand(a(base+n*4),extra,false);dis.enableCodeAnalysis(false);dis.applyTo(currentProgram,monitor);}initial.add(extra);getFunctionAt(a(CODE)).setBody(initial);}
            if(name.equals("existing_prefix")){dis=new DisassembleCommand(a(base),new AddressSet(a(base),a(base+3)),false);dis.enableCodeAnalysis(false);dis.applyTo(currentProgram,monitor);}
            if(name.equals("defined_data"))currentProgram.getListing().createData(a(base),DWordDataType.dataType);
            if(name.equals("other_owner")){var owned=new AddressSet(a(base+8),a(base+15));dis=new DisassembleCommand(a(base+8),owned,true);dis.enableCodeAnalysis(false);dis.applyTo(currentProgram,monitor);currentProgram.getFunctionManager().createFunction("user_case",a(base+8),owned,SourceType.USER_DEFINED);}
            if(name.equals("manual_name"))getFunctionAt(a(CODE)).setName("user_dispatch",SourceType.USER_DEFINED);
            if(name.equals("user_label"))currentProgram.getSymbolTable().createLabel(a(base+8),"user_case_label",SourceType.USER_DEFINED);
            if(name.equals("called_user_label"))currentProgram.getSymbolTable().createLabel(a(CODE+0x200),"user_called_label",SourceType.USER_DEFINED);
            if(name.equals("conflicting_reference"))currentProgram.getReferenceManager().addMemoryReference(a(branch),a(CODE+0xc0),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,-1);
            if(name.equals("interior_entry"))currentProgram.getReferenceManager().addMemoryReference(a(CODE+0xc0),a(branch-4),RefType.UNCONDITIONAL_JUMP,SourceType.USER_DEFINED,-1);
        }finally{currentProgram.endTransaction(tx,true);}
        var f=getFunctionAt(a(CODE));var oldBody=new AddressSet(f.getBody());String oldName=f.getName();var oldRefs=refs(branch);long oldInstructions=currentProgram.getListing().getNumInstructions();int oldFunctions=currentProgram.getFunctionManager().getFunctionCount();
        TaskMonitor task=monitor;
        if(name.startsWith("cancel_"))task=new TaskMonitorAdapter(true){@Override public void checkCancelled() throws CancelledException {
            if(name.equals("cancel_reference")?!refs(branch).equals(oldRefs):f.getBody().contains(a(base)))throw new CancelledException();super.checkCancelled();}};
        boolean cancelled=false;var analyzer=new XenonSwitchAnalyzer();
        try{analyzer.added(currentProgram,name.equals("partial_selection")?new AddressSet(a(CODE)):currentProgram.getMemory(),task,new MessageLog());}catch(CancelledException ex){cancelled=true;}
        if(positive) {
            check(refs(branch).size()==3,"three exact targets "+name);
            check(f.getBody().contains(a(base),a(base+15)),"case body recovered "+name);
            if(nested)check(refs(CODE+0x12c).size()==2&&f.getBody().contains(a(CODE+0x130),a(CODE+0x13f)),"nested complete");
            if(name.equals("called_wrapper"))check(getInstructionAt(a(CODE+0x200))!=null&&getInstructionAt(a(CODE+0x304))!=null&&!f.getBody().contains(a(CODE+0x200))&&refs(CODE+0x20c).size()==1,"direct callees decoded outside caller body");
            var afterBody=new AddressSet(f.getBody());var afterRefs=refs(branch);long afterInstructions=currentProgram.getListing().getNumInstructions();
            analyzer.added(currentProgram,currentProgram.getMemory(),monitor,new MessageLog());
            check(afterRefs.equals(refs(branch))&&afterBody.equals(f.getBody())&&afterInstructions==currentProgram.getListing().getNumInstructions(),"idempotent "+name);
        }else {
            check(oldBody.equals(f.getBody()),"body preserved "+name);check(oldRefs.equals(refs(branch)),"references preserved "+name);
            check(oldInstructions==currentProgram.getListing().getNumInstructions(),"instructions preserved "+name);
        }
        check(cancelled==name.startsWith("cancel_"),"cancellation contract "+name);
        check(f.getName().equals(oldName)&&currentProgram.getFunctionManager().getFunctionCount()==oldFunctions,"names and function population preserved "+name);
    }
    private SortedSet<String> refs(long branch) {
        var out=new TreeSet<String>();for(var r:currentProgram.getReferenceManager().getReferencesFrom(a(branch)))if(r.getReferenceType().isFlow())out.add(r.getToAddress()+"|"+r.getReferenceType()+"|"+r.getSource());return out;
    }
}
