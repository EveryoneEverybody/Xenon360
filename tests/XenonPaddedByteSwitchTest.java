import java.nio.*;
import java.nio.file.*;
import java.util.*;
import java.lang.reflect.*;
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import xenon360.XenonSwitchAnalyzer;
import xenon360.analysis.HalfwordSwitchRecovery;
import xenon360.analysis.XenonEvidence;

/** Byte-array target oracle, original p-code execution, and failure atomicity. */
public class XenonPaddedByteSwitchTest extends GhidraScript {
    private int checks,executions;private final List<Object> results=new ArrayList<>();
    private void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private Address a(long x){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);}
    private int hi(long x){return 0x3d800000|((int)((x+0x8000)>>>16)&65535);}
    private int lo(long x){return 0x398c0000|((int)x&65535);}
    private int[] words(long start,long table,long base,long fallback,int count,int index,int scale){
        int cmp=0x2b000000|(index<<16)|(count-1),bgt=0x41990000|((int)(fallback-start-4)&65532),load=0x7c0c00ae|(index<<11);
        if(scale==4)return new int[]{cmp,bgt,hi(table),lo(table),load,0x5400103a,hi(base),lo(base),0x7d8c0214,0x7d8903a6,0x60000000,0x4e800420};
        return new int[]{cmp,bgt,hi(table),lo(table),load,hi(base),lo(base),0x7d8c0214,0x7d8903a6,0x60000000,0x60000000,0x4e800420};
    }
    private SortedSet<String> allRefs(){var s=new TreeSet<String>();var it=currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(),true);while(it.hasNext())for(var r:currentProgram.getReferenceManager().getReferencesFrom(it.next()))s.add(r.getFromAddress()+"|"+r.getToAddress()+"|"+r.getReferenceType()+"|"+r.getSource()+"|"+r.getOperandIndex());return s;}
    private SortedSet<String> targets(long b){var s=new TreeSet<String>();for(var r:currentProgram.getReferenceManager().getReferencesFrom(a(b)))if(r.getReferenceType().isJump())s.add(r.getToAddress().toString());return s;}
    private Object snapshot(){var funcs=new TreeMap<String,String>();for(var f:currentProgram.getFunctionManager().getFunctions(true))funcs.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody());var syms=new TreeSet<String>();for(var s:currentProgram.getSymbolTable().getAllSymbols(true))syms.add(s.getAddress()+"|"+s.getName(true)+"|"+s.getSource());var data=new TreeSet<String>();for(var d:currentProgram.getListing().getDefinedData(true))data.add(d.getAddress()+"|"+d.getLength()+"|"+d.getDataType());return List.of(allRefs(),funcs,syms,data,currentProgram.getListing().getNumInstructions(),currentProgram.getBookmarkManager().getBookmarkCount());}
    private boolean preflight(long branch)throws Exception{
        var f=getFunctionContaining(a(branch));Method match=HalfwordSwitchRecovery.class.getDeclaredMethod("match",Program.class,Address.class,Function.class);match.setAccessible(true);Object table=match.invoke(null,currentProgram,a(branch),f);if(table==null)return false;
        Method preflight=Arrays.stream(HalfwordSwitchRecovery.class.getDeclaredMethods()).filter(m->m.getName().equals("preflight")).findFirst().orElseThrow();preflight.setAccessible(true);return preflight.invoke(null,currentProgram,f,table,monitor)!=null;
    }
    @Override protected void run()throws Exception {
        String[] names={"min_scaled","min_unscaled","typical_scaled","typical_unscaled","max_scaled","max_unscaled","index_r0","index_r4","index_r10","index_r31","negative_low","odd_byte_address","zero_last","existing_targets","existing_prefix","nested_two","nested_max32",
            "wrong_guard","signed_guard","wrong_cr","wrong_index","wrong_condition","missing_guard","index_clobbered","wrong_ctr","indirect_call","wrong_width","signed_entry_transform","case_budget","degenerate_count","writable_table","executable_table","uninitialized_table","truncated_table","unaligned_target","nonexec_target","target_outside_budget","other_owner","manual_owner","user_label","imported_label","table_user_label","table_structure","table_wrong_width","target_structure","conflicting_reference","interior_entry","interior_target","branch_override","target_override","unsupported_computed","callback_lookalike","byte_budget","nested_invalid","nested_over33","cancel_disassembly","cancel_reference","cancel_body","fail_transaction","partial_selection"};
        var original=currentProgram;
        for(String name:names){int before=checks,executed=executions;var p=new ProgramDB(name,original.getLanguage(),original.getLanguage().getCompilerSpecByID(original.getCompilerSpec().getCompilerSpecID()),this);currentProgram=p;try{fixture(name);results.add(Map.of("name",name,"status","PASS","checks",checks-before,"executions",executions-executed));}finally{currentProgram=original;p.release(this);}}
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("status","PASS","checks",checks,"fixtures",names.length,"executions",executions,"results",results));println("XENON_PADDED_BYTE_TEST_PASS checks="+checks+" executions="+executions);
    }
    private void fixture(String name)throws Exception {
        boolean positive=Set.of("min_scaled","min_unscaled","typical_scaled","typical_unscaled","max_scaled","max_unscaled","index_r0","index_r4","index_r10","index_r31","negative_low","odd_byte_address","zero_last","existing_targets","existing_prefix","nested_two","nested_max32").contains(name);
        long codeStart=name.equals("negative_low")?0x84018000L:0x84010000L,tableStart=0x84000000L+(name.equals("negative_low")?0x8000:0)+(name.equals("odd_byte_address")?1:0);
        long branch=codeStart+44,base=codeStart+0x200,fallback=codeStart+0x1400;
        int count=name.startsWith("min_")?2:name.startsWith("max_")?256:6,scale=name.endsWith("unscaled")?1:4,index=name.startsWith("index_r")?Integer.parseInt(name.substring(7)):11;
        if(name.equals("index_clobbered"))index=12;if(name.equals("case_budget"))count=257;if(name.equals("degenerate_count"))count=1;
        if(name.equals("unaligned_target"))base++;if(name.equals("nonexec_target"))base=tableStart;if(name.equals("target_outside_budget"))base=codeStart+0x2000;
        boolean nested=name.startsWith("nested_");int tables=name.equals("nested_max32")?32:name.equals("nested_over33")?33:nested?2:1;
        byte[] code=new byte[0x3000],data=new byte[0x500];ByteBuffer bytes=ByteBuffer.wrap(code).order(ByteOrder.BIG_ENDIAN);
        int[] pattern=words(codeStart,tableStart,base,fallback,count,index,scale);
        switch(name){
            case "wrong_guard":pattern[0]^=0x10000;break;
            case "signed_guard":pattern[0]|=0x04000000;break;
            case "wrong_cr":pattern[0]^=0x00800000;break;
            case "wrong_index":pattern[4]^=0x800;break;
            case "wrong_condition":pattern[1]=0x41980000|(pattern[1]&65535);break;
            case "missing_guard":pattern[0]=0x60000000;break;
            case "wrong_ctr":pattern[9]=0x7c0903a6;break;
            case "indirect_call":pattern[11]=0x4e800421;break;
            case "wrong_width":pattern[4]=0x7c0c5a2e;break;
            case "signed_entry_transform":pattern[5]=0x7c000774;break;
            case "callback_lookalike":pattern[4]=0x800c0000;break;
        }
        for(int n=0;n<12;n++)bytes.putInt(n*4,pattern[n]);
        for(int n=0;n<count;n++){data[n]=(byte)(scale==4?n:n*4);long target=base+(data[n]&255)*(long)scale;if(target>=codeStart&&target+4<=codeStart+code.length)bytes.putInt((int)(target-codeStart),0x4e800020);}
        if(name.equals("zero_last"))data[count-1]=0;
        bytes.putInt(0x1400,0x4e800020);
        if(name.equals("unsupported_computed"))bytes.putInt((int)(base-codeStart),0x4e800420);
        if(name.equals("byte_budget")){for(int at=0x200;at<0x1600;at+=4)bytes.putInt(at,0x60000000);bytes.putInt(0x1600,0x4e800020);}
        if(name.equals("interior_target")){pattern=words(codeStart,tableStart,codeStart,fallback,count,index,scale);for(int n=0;n<12;n++)bytes.putInt(n*4,pattern[n]);data[0]=1;}
        if(nested){count=2;scale=4;index=11;for(int t=0;t<tables;t++){long entry=codeStart+t*0x60L,leaf=entry+48;int[] w=words(entry,tableStart+t*4L,leaf,fallback,2,11,4);for(int n=0;n<12;n++)bytes.putInt(t*0x60+n*4,w[n]);bytes.putInt(t*0x60+48,0x4e800020);bytes.putInt(t*0x60+52,0x4e800020);data[t*4]=0;data[t*4+1]=(byte)(t==tables-1?1:12);}base=codeStart+48;if(name.equals("nested_invalid"))bytes.putInt(0x60,0x2f0b0001);}
        var expected=new TreeSet<String>();for(int n=0;n<count;n++)expected.add(a(base+(data[n]&255)*(long)scale).toString());
        var initial=new AddressSet(a(codeStart),a(branch+3));initial.add(a(fallback),a(fallback+3));
        int tx=currentProgram.startTransaction("Fixture");
        try {
            var text=currentProgram.getMemory().createInitializedBlock("text",a(codeStart),new java.io.ByteArrayInputStream(code),code.length,monitor,false);text.setExecute(true);text.setWrite(false);
            var table=name.equals("uninitialized_table")?currentProgram.getMemory().createUninitializedBlock("table",a(tableStart),data.length,false):currentProgram.getMemory().createInitializedBlock("table",a(tableStart),new java.io.ByteArrayInputStream(data),name.equals("truncated_table")?count-1:data.length,monitor,false);
            table.setWrite(name.equals("writable_table"));table.setExecute(name.equals("executable_table"));
            var dis=new DisassembleCommand(a(codeStart),initial,true);dis.enableCodeAnalysis(false);check(dis.applyTo(currentProgram,monitor),"fixture decode "+name);
            currentProgram.getFunctionManager().createFunction(null,a(codeStart),initial,SourceType.ANALYSIS);
            if(name.equals("existing_targets")||name.equals("existing_prefix")){var extra=new AddressSet();for(String s:expected)extra.add(toAddr(s),toAddr(s).add(3));dis=new DisassembleCommand(extra,extra,false);dis.enableCodeAnalysis(false);check(dis.applyTo(currentProgram,monitor),"existing target decode");if(name.equals("existing_targets")){initial.add(extra);getFunctionAt(a(codeStart)).setBody(initial);}}
            if(name.equals("other_owner")){currentProgram.getFunctionManager().createFunction("other",a(base),new AddressSet(a(base),a(base+3)),SourceType.USER_DEFINED);}
            if(name.equals("manual_owner"))getFunctionAt(a(codeStart)).setName("manual",SourceType.USER_DEFINED);
            if(name.equals("user_label")||name.equals("imported_label"))currentProgram.getSymbolTable().createLabel(a(base),"protected_case",name.equals("user_label")?SourceType.USER_DEFINED:SourceType.IMPORTED);
            if(name.equals("table_user_label"))currentProgram.getSymbolTable().createLabel(a(tableStart),"protected_table",SourceType.USER_DEFINED);
            if(name.equals("table_structure")||name.equals("target_structure")){var structure=new StructureDataType("ManualStructure",4);currentProgram.getListing().createData(a(name.equals("table_structure")?tableStart:base),structure);}
            if(name.equals("table_wrong_width"))currentProgram.getListing().createData(a(tableStart),WordDataType.dataType);
            if(name.equals("conflicting_reference"))currentProgram.getReferenceManager().addMemoryReference(a(branch),a(fallback),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,-1);
            if(name.equals("interior_entry"))currentProgram.getReferenceManager().addMemoryReference(a(fallback),a(branch-4),RefType.UNCONDITIONAL_JUMP,SourceType.USER_DEFINED,-1);
            if(name.equals("branch_override"))getInstructionAt(a(branch)).setFlowOverride(FlowOverride.CALL);
            if(name.equals("target_override")){dis=new DisassembleCommand(a(base),new AddressSet(a(base),a(base+3)),false);dis.enableCodeAnalysis(false);check(dis.applyTo(currentProgram,monitor),"override target decode");getInstructionAt(a(base)).setFlowOverride(FlowOverride.BRANCH);}
        }finally{currentProgram.endTransaction(tx,true);}
        Object before=snapshot();long mod=currentProgram.getModificationNumber();boolean planned=preflight(branch);
        check(mod==currentProgram.getModificationNumber()&&before.equals(snapshot()),"preflight is read-only "+name);
        if(positive)check(planned,"positive preflight "+name);
        else if(!name.startsWith("cancel_")&&!Set.of("fail_transaction","partial_selection","manual_owner","branch_override").contains(name))check(!planned,"negative preflight "+name);
        var f=getFunctionAt(a(codeStart));var oldBody=new AddressSet(f.getBody());var oldRefs=allRefs();long baseFinal=base;
        TaskMonitor task=monitor;
        if(name.startsWith("cancel_")||name.equals("fail_transaction"))task=new TaskMonitorAdapter(true){@Override public void checkCancelled()throws CancelledException{boolean hit=name.equals("cancel_disassembly")?getInstructionAt(a(baseFinal))!=null:name.equals("cancel_body")?!oldBody.equals(f.getBody()):!oldRefs.equals(allRefs());if(hit){if(name.equals("fail_transaction"))throw new IllegalStateException("injected mutation failure");throw new CancelledException();}super.checkCancelled();}};
        boolean cancelled=false,ok=false;var analyzer=new XenonSwitchAnalyzer();
        String oldSummary=currentProgram.getOptions("Xenon360").getString("Switch evidence JSON",null);
        try{ok=analyzer.added(currentProgram,name.equals("partial_selection")?new AddressSet(a(branch)):currentProgram.getMemory(),task,new MessageLog());}catch(CancelledException ex){cancelled=true;}
        if(positive){check(ok,"analyzer succeeds "+name);check(targets(branch).equals(expected),"exact distinct target set "+name);for(String target:expected)check(getInstructionAt(toAddr(target))!=null&&f.getBody().contains(toAddr(target)),"instruction and owner "+name);
            Object after=snapshot();check(analyzer.added(currentProgram,currentProgram.getMemory(),monitor,new MessageLog()),"repeat succeeds "+name);check(after.equals(snapshot()),"idempotent refs/instructions/owners/symbols/data "+name);
            if(!nested){var emu=new EmulatorHelper(currentProgram);try{for(int n=0;n<count+2;n++){long input=n==count+1?0xffffffffL:n;for(int r=0;r<32;r++)emu.writeRegister("r"+r,0);emu.writeRegister("r"+index,input);emu.writeRegister(emu.getPCRegister(),codeStart);int steps=0;do{check(++steps<=12&&emu.step(monitor),"emulator steps "+name);}while(emu.getExecutionAddress().getOffset()>=codeStart&&emu.getExecutionAddress().getOffset()<=branch);long target=n<count?base+(data[n]&255)*(long)scale:fallback;check(emu.getExecutionAddress().equals(a(target)),"first/last/all indices and rejected out-of-range "+name+" "+input);executions++;}}finally{emu.dispose();}}
            if(nested)check(currentProgram.getOptions("Xenon360").getString("Switch evidence JSON","").contains("validated_dispatches"),"nested evidence");
        }else{check(before.equals(snapshot()),"all program structures preserved "+name);if(name.startsWith("cancel_")||name.equals("fail_transaction"))check(Objects.equals(oldSummary,currentProgram.getOptions("Xenon360").getString("Switch evidence JSON",null)),"transaction metadata rollback "+name);if(name.equals("fail_transaction"))check(!ok,"failed transaction returns false");}
        check(cancelled==name.startsWith("cancel_"),"cancellation contract "+name);
    }
}
