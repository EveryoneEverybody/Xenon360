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
import xenon360.analysis.AbsoluteWordSwitchRecovery;
import xenon360.analysis.XenonEvidence;

/** Synthetic relocations of the independently executed original inline pattern.
 * Expected targets come from the fixture table bytes, never from the matcher. */
public class XenonAbsoluteWordSwitchTest extends GhidraScript {
    private int checks,executions;private final List<Object> results=new ArrayList<>();
    private void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private Address a(long x){return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(x);}
    private int[] words(long start,long table,long fallback,int count,int index){return new int[]{
        0x2b000000|(index<<16)|(count-1),0x41990000|((int)(fallback-start-4)&65532),
        0x3d800000|((int)((table+0x8000)>>>16)&65535),0x398c0000|((int)table&65535),
        0x5400103a|(index<<21),0x7c0c002e,0x7c0903a6,0x4e800420};}
    private SortedSet<String> refs(){var set=new TreeSet<String>();var it=currentProgram.getReferenceManager().getReferenceSourceIterator(currentProgram.getMemory(),true);while(it.hasNext())for(var r:currentProgram.getReferenceManager().getReferencesFrom(it.next()))set.add(r.getFromAddress()+"|"+r.getToAddress()+"|"+r.getReferenceType()+"|"+r.getSource()+"|"+r.getOperandIndex());return set;}
    private SortedSet<String> targets(long b){var set=new TreeSet<String>();for(var r:currentProgram.getReferenceManager().getReferencesFrom(a(b)))if(r.getReferenceType().isJump())set.add(r.getToAddress().toString());return set;}
    private Object snapshot(){var funcs=new TreeMap<String,String>();for(var f:currentProgram.getFunctionManager().getFunctions(true))funcs.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody());var symbols=new TreeSet<String>();for(var s:currentProgram.getSymbolTable().getAllSymbols(true))symbols.add(s.getAddress()+"|"+s.getName(true)+"|"+s.getSource());var data=new TreeSet<String>();for(var d:currentProgram.getListing().getDefinedData(true))data.add(d.getAddress()+"|"+d.getLength()+"|"+d.getDataType());var code=new TreeSet<String>();for(var i:currentProgram.getListing().getInstructions(true))code.add(i.getAddress()+"|"+i+"|"+i.getFlowOverride()+"|"+i.getFallThrough());return List.of(refs(),funcs,symbols,data,code,currentProgram.getBookmarkManager().getBookmarkCount());}
    private boolean preflight(long branch)throws Exception {
        var owner=getFunctionContaining(a(branch));Method match=AbsoluteWordSwitchRecovery.class.getDeclaredMethod("match",Program.class,Address.class,Function.class);match.setAccessible(true);Object table=match.invoke(null,currentProgram,a(branch),owner);if(table==null)return false;
        Method pre=Arrays.stream(AbsoluteWordSwitchRecovery.class.getDeclaredMethods()).filter(m->m.getName().equals("preflight")).findFirst().orElseThrow();pre.setAccessible(true);
        try{return pre.invoke(null,currentProgram,owner,table,monitor)!=null;}catch(InvocationTargetException ex){if(ex.getCause().getClass().getSimpleName().equals("Rejected"))return false;throw ex;}
    }
    private void decode(AddressSet set)throws Exception{var d=new DisassembleCommand(set,set,false);d.enableCodeAnalysis(false);check(d.applyTo(currentProgram,monitor),"fixture decoding must succeed");}
    @Override protected void run()throws Exception {
        String[] names={"minimum","typical","maximum512","index_r0","index_r4","index_r29","index_r31","negative_low","duplicate_entries","default_is_case","existing_owner_targets","existing_unowned_instructions","existing_refs","pointer_scalars","dword_scalars","direct_call","tailcall",
            "wrong_guard","missing_guard","signed_guard","wrong_cr","wrong_condition","wrong_index","clobbered_index","wrong_shift","wrong_load","signed_transform","wrong_ctr","callback_lookalike","indirect_call","nonlocal_guard","other_schedule","little_endian_entries","misaligned_target","target_outside_block","target_nonexec_block","table_truncated","uninitialized_table","address_overflow","writable_storage","unreadable_storage","nonexecuting_storage","noninline_executable_table","table_instruction","table_structure","table_array","table_wrong_width","table_user_symbol","table_imported_symbol","table_interior_symbol","table_owner","table_incoming_flow","conflicting_table_ref","target_structure","target_interior_data","target_user_symbol","target_imported_symbol","target_interior_symbol","foreign_owner","target_interior_owner","manual_owner","imported_owner","conflicting_reference","guard_bypass","guard_predecessor_jump","guard_interior_byte_entry","branch_override","fallthrough_override","target_override","target_fallthrough_override","foreign_incoming_flow","unknown_incoming_flow","jump_into_table","jump_bypasses_guard","unsupported_computed","nested_two","nested32","nested33","expansion_budget","address_window_budget","entry_budget513","degenerate_count","default_alias_after_native_pruning","cancel_disassembly","cancel_reference","cancel_body","fail_reference","fail_body","partial_selection"};
        var original=currentProgram;Path receipt=Path.of(getScriptArgs()[0]);
        for(String name:names){int before=checks,executed=executions;var p=new ProgramDB(name,original.getLanguage(),original.getLanguage().getCompilerSpecByID(original.getCompilerSpec().getCompilerSpecID()),this);currentProgram=p;
            try{fixture(name);results.add(Map.of("name",name,"status","PASS","checks",checks-before,"executions",executions-executed));}
            catch(Throwable ex){XenonEvidence.writeAtomic(Path.of(receipt+".failed.json"),Map.of("status","FAIL","fixture",name,"error",ex.toString(),"completed",results));throw ex;}
            finally{currentProgram=original;p.release(this);}}
        XenonEvidence.writeAtomic(receipt,Map.of("status","PASS","checks",checks,"fixtures",names.length,"executions",executions,"results",results));println("XENON_ABSOLUTE_WORD_TEST_PASS checks="+checks+" executions="+executions);
    }
    private void fixture(String name)throws Exception {
        boolean positive=Set.of("minimum","typical","maximum512","index_r0","index_r4","index_r29","index_r31","negative_low","duplicate_entries","existing_owner_targets","existing_unowned_instructions","existing_refs","pointer_scalars","dword_scalars","direct_call","tailcall").contains(name);
        long start=name.equals("negative_low")?0x84017fe4L:0x84010000L,branch=start+28,table=start+32,fallback=start+0x3000;
        int count=name.equals("minimum")?2:name.equals("maximum512")?512:name.equals("entry_budget513")?513:name.equals("default_alias_after_native_pruning")?29:name.equals("degenerate_count")?1:6,index=name.startsWith("index_r")?Integer.parseInt(name.substring(7)):11;
        if(name.equals("clobbered_index"))index=12;
        long first=table+count*4L;if(Set.of("table_truncated","uninitialized_table").contains(name))first=start+0x1000;
        if(name.equals("address_window_budget"))first=start+0x1800;
        long[] entries=new long[count];for(int n=0;n<count;n++)entries[n]=first+n*4L;
        if(name.equals("duplicate_entries"))entries[count-1]=entries[0];
        if(name.equals("default_is_case"))entries[count-1]=fallback;
        if(name.equals("default_alias_after_native_pruning")){for(int n=0;n<count;n++)entries[n]=first+(n%15)*4L;entries[count-1]=fallback;}
        if(name.equals("misaligned_target"))entries[0]++;
        if(name.equals("target_outside_block"))entries[0]=start+0x5000;
        if(name.equals("target_nonexec_block"))entries[0]=start+0x5000;
        int[] pattern=words(start,table,fallback,count,index);
        switch(name){
            case "wrong_guard":pattern[0]^=0x10000;break;case "missing_guard":case "nonlocal_guard":pattern[0]=0x60000000;break;
            case "signed_guard":pattern[0]|=0x04000000;break;case "wrong_cr":pattern[0]^=0x00800000;break;case "wrong_condition":pattern[1]^=0x10000;break;
            case "wrong_index":pattern[4]^=0x200000;break;case "wrong_shift":pattern[4]=0x5560083c;break;
            case "wrong_load":pattern[5]=0x7c0c022e;break;case "signed_transform":pattern[6]=0x7c000774;break;
            case "wrong_ctr":pattern[6]=0x7d8903a6;break;case "callback_lookalike":pattern[5]=0x800c0000;break;
            case "indirect_call":pattern[7]=0x4e800421;break;
            case "other_schedule":int tmp=pattern[3];pattern[3]=pattern[4];pattern[4]=tmp;break;
            case "address_overflow":pattern[2]=0x3d800000;pattern[3]=0x398cfffc;break;
            case "noninline_executable_table":pattern=words(start,table+0x2000,fallback,count,index);break;
        }
        byte[] code=new byte[0x4000];ByteBuffer bytes=ByteBuffer.wrap(code).order(ByteOrder.BIG_ENDIAN);
        for(int n=0;n<8;n++)bytes.putInt(n*4,pattern[n]);
        for(int n=0;n<count;n++){bytes.putInt(32+n*4,name.equals("little_endian_entries")?Integer.reverseBytes((int)entries[n]):(int)entries[n]);if(entries[n]>=start&&entries[n]+4<=start+code.length)bytes.putInt((int)(entries[n]-start),0x4e800020);}
        bytes.putInt(0x3000,0x4e800020);
        if(name.equals("nonlocal_guard"))bytes.putInt(0x2000,0x2b0b0005);
        if(name.equals("unsupported_computed"))bytes.putInt((int)(first-start),0x4e800420);
        if(name.equals("jump_into_table")||name.equals("jump_bypasses_guard")){long to=name.equals("jump_into_table")?table:start+4;bytes.putInt((int)(first-start),0x48000000|((int)(to-first)&0x03fffffc));}
        if(name.equals("expansion_budget")){for(int at=(int)(first-start);at<0x1800;at+=4)bytes.putInt(at,0x60000000);bytes.putInt(0x1800,0x4e800020);}
        boolean nested=name.startsWith("nested");
        if(nested){int tables=name.equals("nested_two")?2:name.equals("nested32")?32:33;entries[0]=start+0x100;bytes.putInt(32,(int)entries[0]);for(int t=1;t<tables;t++){int off=0x100+(t-1)*0x60;long at=start+off;int[] w=words(at,at+32,fallback,2,11);for(int n=0;n<8;n++)bytes.putInt(off+n*4,w[n]);bytes.putInt(off+32,(int)(at+40));bytes.putInt(off+36,(int)(t==tables-1?at+44:at+0x60));bytes.putInt(off+40,0x4e800020);bytes.putInt(off+44,0x4e800020);}}
        if(name.equals("direct_call")||name.equals("tailcall")){bytes.putInt((int)(first-start),0x48000000|((int)(start+0x2000-first)&0x03fffffc)|(name.equals("direct_call")?1:0));bytes.putInt(0x2000,0x4e800020);}
        var expected=new TreeSet<String>();for(long value:entries)expected.add(a(value).toString());
        var initial=new AddressSet(a(start),a(branch+3));initial.add(a(fallback),a(fallback+3));
        int tx=currentProgram.startTransaction("fixture");try {
            boolean split=Set.of("table_truncated","uninitialized_table").contains(name);int length=split?32+(name.equals("table_truncated")?count*4-1:0):code.length;
            var text=currentProgram.getMemory().createInitializedBlock("text",a(start),new java.io.ByteArrayInputStream(code),length,monitor,false);text.setExecute(true);text.setWrite(false);
            if(split){var suffix=currentProgram.getMemory().createInitializedBlock("cases",a(first),new java.io.ByteArrayInputStream(Arrays.copyOfRange(code,(int)(first-start),code.length)),code.length-(first-start),monitor,false);suffix.setExecute(true);suffix.setWrite(false);if(name.equals("uninitialized_table")){var b=currentProgram.getMemory().createUninitializedBlock("table",a(table),count*4,false);b.setExecute(true);b.setWrite(false);}}
            if(name.equals("target_nonexec_block")){var b=currentProgram.getMemory().createInitializedBlock("data",a(start+0x5000),4,(byte)0,monitor,false);b.setExecute(false);b.setWrite(false);}
            decode(initial);currentProgram.getFunctionManager().createFunction(null,a(start),initial,SourceType.ANALYSIS);
            if(name.equals("writable_storage"))text.setWrite(true);if(name.equals("unreadable_storage"))text.setRead(false);if(name.equals("nonexecuting_storage"))text.setExecute(false);
            if(name.equals("manual_owner")||name.equals("imported_owner"))getFunctionAt(a(start)).setName("protected",name.equals("manual_owner")?SourceType.USER_DEFINED:SourceType.IMPORTED);
            if(Set.of("existing_owner_targets","existing_unowned_instructions","existing_refs","target_override","target_fallthrough_override").contains(name)) {var set=new AddressSet();for(String target:expected)set.add(toAddr(target),toAddr(target).add(3));decode(set);if(name.equals("existing_owner_targets")){initial.add(set);getFunctionAt(a(start)).setBody(initial);}if(name.equals("existing_refs"))for(String target:expected)currentProgram.getReferenceManager().addMemoryReference(a(branch),toAddr(target),RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);}
            if(name.equals("pointer_scalars")||name.equals("dword_scalars"))for(int n=0;n<count;n++)currentProgram.getListing().createData(a(table+n*4L),name.equals("pointer_scalars")?new PointerDataType(DWordDataType.dataType,4):DWordDataType.dataType);
            if(name.equals("table_instruction"))decode(new AddressSet(a(table),a(table+3)));
            if(name.equals("table_structure"))currentProgram.getListing().createData(a(table),new StructureDataType("held",8));
            if(name.equals("table_array"))currentProgram.getListing().createData(a(table),new ArrayDataType(DWordDataType.dataType,count,4));
            if(name.equals("table_wrong_width"))currentProgram.getListing().createData(a(table),WordDataType.dataType);
            if(name.equals("target_structure"))currentProgram.getListing().createData(a(first),new StructureDataType("heldTarget",4));
            if(name.equals("target_interior_data"))currentProgram.getListing().createData(a(first+1),ByteDataType.dataType);
            for(String where:List.of("table","target"))for(String kind:List.of("user","imported","interior"))if(name.equals(where+"_"+kind+"_symbol"))currentProgram.getSymbolTable().createLabel(a((where.equals("table")?table:first)+(kind.equals("interior")?1:0)),"held",kind.equals("imported")?SourceType.IMPORTED:SourceType.USER_DEFINED);
            if(name.equals("foreign_owner")||name.equals("target_interior_owner")||name.equals("table_owner")){long at=name.equals("foreign_owner")?first:name.equals("target_interior_owner")?first+1:table;currentProgram.getFunctionManager().createFunction("foreign",a(at),new AddressSet(a(at),a(at+3)),SourceType.ANALYSIS);}
            if(name.equals("tailcall"))currentProgram.getFunctionManager().createFunction(null,a(start+0x2000),new AddressSet(a(start+0x2000),a(start+0x2003)),SourceType.ANALYSIS);
            if(name.equals("default_alias_after_native_pruning"))for(String t:expected)if(!toAddr(t).equals(a(fallback)))currentProgram.getReferenceManager().addMemoryReference(a(branch),toAddr(t),RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);
            if(name.equals("conflicting_reference"))currentProgram.getReferenceManager().addMemoryReference(a(branch),a(fallback),RefType.COMPUTED_JUMP,SourceType.USER_DEFINED,-1);
            if(name.equals("conflicting_table_ref"))currentProgram.getReferenceManager().addMemoryReference(a(table),a(fallback),RefType.DATA,SourceType.ANALYSIS,-1);
            if(name.equals("table_incoming_flow"))currentProgram.getReferenceManager().addMemoryReference(a(fallback),a(table),RefType.UNCONDITIONAL_JUMP,SourceType.ANALYSIS,-1);
            if(Set.of("guard_bypass","guard_predecessor_jump","guard_interior_byte_entry").contains(name))currentProgram.getReferenceManager().addMemoryReference(a(name.equals("guard_predecessor_jump")?start:fallback),a(start+4+(name.equals("guard_interior_byte_entry")?1:0)),RefType.UNCONDITIONAL_JUMP,SourceType.ANALYSIS,-1);
            if(name.equals("branch_override"))getInstructionAt(a(branch)).setFlowOverride(FlowOverride.CALL);
            if(name.equals("fallthrough_override"))getInstructionAt(a(branch)).setFallThrough(a(table));
            if(name.equals("target_override"))getInstructionAt(a(first)).setFlowOverride(FlowOverride.BRANCH);
            if(name.equals("target_fallthrough_override"))getInstructionAt(a(first)).setFallThrough(a(fallback));
            if(name.equals("foreign_incoming_flow")||name.equals("unknown_incoming_flow")){if(name.equals("foreign_incoming_flow"))currentProgram.getFunctionManager().createFunction("other",a(start+0x2000),new AddressSet(a(start+0x2000),a(start+0x2003)),SourceType.ANALYSIS);currentProgram.getReferenceManager().addMemoryReference(a(start+0x2000),a(first),RefType.UNCONDITIONAL_JUMP,SourceType.ANALYSIS,-1);}
        }finally{currentProgram.endTransaction(tx,true);}
        Object before=snapshot();long mod=currentProgram.getModificationNumber();boolean plan=preflight(branch);
        check(mod==currentProgram.getModificationNumber()&&before.equals(snapshot()),"read-only preflight "+name);
        boolean fault=name.startsWith("cancel_")||name.startsWith("fail_");check(plan==(positive||fault||name.equals("partial_selection")),"preflight outcome "+name);
        var owner=getFunctionAt(a(start));var oldBody=new AddressSet(owner.getBody());var oldTargets=targets(branch);long caseAddress=first;
        TaskMonitor task=monitor;if(fault)task=new TaskMonitorAdapter(true){@Override public void checkCancelled()throws CancelledException{boolean hit=name.endsWith("disassembly")?getInstructionAt(a(caseAddress))!=null:name.endsWith("body")?!oldBody.equals(owner.getBody()):!oldTargets.equals(targets(branch));if(hit){if(name.startsWith("fail_"))throw new IllegalStateException("injected word transaction failure "+name);throw new CancelledException();}super.checkCancelled();}};
        String metadata=currentProgram.getOptions("Xenon360").getString("Switch evidence JSON",null);boolean cancelled=false,ok=false;var log=new MessageLog();var analyzer=new XenonSwitchAnalyzer();
        try{ok=analyzer.added(currentProgram,name.equals("partial_selection")?new AddressSet(a(branch)):currentProgram.getMemory(),task,log);}catch(CancelledException ex){cancelled=true;}
        check(cancelled==name.startsWith("cancel_"),"cancellation observed "+name);
        if(positive){check(ok,"successful analyzer "+name+" "+log);check(targets(branch).equals(expected),"complete exact target set "+name);for(String target:expected)check(getInstructionAt(toAddr(target))!=null&&owner.getBody().contains(toAddr(target)),"target instruction and owner "+name);
            Object after=snapshot();check(analyzer.added(currentProgram,currentProgram.getMemory(),monitor,new MessageLog()),"repeat analyzer "+name);check(after.equals(snapshot()),"repeat graph/data/symbol/reference idempotency "+name);
            var emu=new EmulatorHelper(currentProgram);try{for(int n=0;n<count+3;n++){long input=n<count?n:n==count?count:n==count+1?0xffffffffL:0x80000000L;for(int r=0;r<32;r++)emu.writeRegister("r"+r,0x1234567800000000L+r);emu.writeRegister("r"+index,input);emu.writeRegister(emu.getPCRegister(),start);int steps=0;do{check(++steps<=8&&emu.step(monitor),"original schedule p-code execution "+name);}while(emu.getExecutionAddress().getOffset()>=start&&emu.getExecutionAddress().getOffset()<=branch);check(emu.getExecutionAddress().equals(a(n<count?entries[n]:fallback)),"independent index target "+name);executions++;}}finally{emu.dispose();}
        }else{check(before.equals(snapshot()),"all structures preserved "+name);if(fault){check(Objects.equals(metadata,currentProgram.getOptions("Xenon360").getString("Switch evidence JSON",null)),"metadata rollback "+name);if(name.startsWith("fail_"))check(!ok&&log.toString().contains("injected word transaction failure"),"injected failure actually reached "+name);}}
    }
}
