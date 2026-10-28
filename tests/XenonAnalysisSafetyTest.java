import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.ToolOptions;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.FlowOverride;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.*;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import xenon360.*;
import xenon360.analysis.*;

public class XenonAnalysisSafetyTest extends GhidraScript {
    private int checks;
    private void check(boolean value,String message) {checks++;if(!value)throw new AssertionError(message);}
    private void string(byte[] bytes,int offset,String value) {
        byte[] data=value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        System.arraycopy(data,0,bytes,offset,data.length);
    }
    @Override protected void run() throws Exception {
        var imported=currentProgram;
        var isolated=new ProgramDB("Xenon360 safety",imported.getLanguage(),
            imported.getLanguage().getCompilerSpecByID(imported.getCompilerSpec().getCompilerSpecID()),this);
        currentProgram=isolated;
        try {
            int copy=isolated.startTransaction("Copy synthetic fixture");
            try {
                for(var original:imported.getMemory().getBlocks()) {
                    if(!original.isInitialized())continue;
                    byte[] bytes=new byte[(int)original.getSize()];original.getBytes(original.getStart(),bytes);
                    var block=isolated.getMemory().createInitializedBlock(original.getName(),toAddr(original.getStart().getOffset()),
                        new java.io.ByteArrayInputStream(bytes),bytes.length,monitor,false);
                    block.setExecute(original.isExecute());
                }
                isolated.getOptions("Xenon360").setString("Source SHA-256",XenonEvidence.sourceHash(imported));
                XenonCompilerHelperBootstrap.apply(isolated,monitor);
                new DisassembleCommand(toAddr(0x82001000L),null,true).applyTo(isolated,monitor);
            } finally {isolated.endTransaction(copy,true);}
            test();
        } finally {currentProgram=imported;isolated.release(this);}
    }
    private void test() throws Exception {
        byte[] data=new byte[1024],code=new byte[256];
        var d=ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);var c=ByteBuffer.wrap(code).order(ByteOrder.BIG_ENDIAN);
        for(int i=0;i<2;i++) {
            int off=i*0x40;String name=i==0?"hkFixtureOne":"hkFixtureTwo";
            string(data,0x100+i*0x80,name);string(data,0x140+i*0x80,"!"+name);
            d.putInt(off,0x83000100+i*0x80).putInt(off+4,0x83000140+i*0x80)
             .putInt(off+8,0x83001000+i*0x80).putInt(off+12,0x83001040+i*0x80)
             .putInt(off+16,0x83000300+i*8).putInt(off+20,16+i*16).putInt(0x300+i*8,0x83001040+i*0x80);
            c.putInt(i*0x80,0x38630001).putInt(i*0x80+4,0x4e800020)
             .putInt(i*0x80+0x40,0x38630002).putInt(i*0x80+0x44,0x4e800020);
        }
        c.putInt(0xd0,0x4bffff30); // b 0x83001000: established entry, explicit tail.
        c.putInt(0xe0,0x48000f20); // b 0x83002000: unresolved outside the bound.
        c.putInt(0xf0,0x4bffff14); // b 0x83001004: interior of an existing owner.
        int tx=currentProgram.startTransaction("Safety fixtures");
        try {
            var memory=currentProgram.getMemory();
            memory.createInitializedBlock("havok_test_data",toAddr(0x83000000L),new java.io.ByteArrayInputStream(data),data.length,monitor,false);
            var block=memory.createInitializedBlock("havok_test_code",toAddr(0x83001000L),new java.io.ByteArrayInputStream(code),code.length,monitor,false);
            block.setExecute(true);
            for(long at:new long[]{0x83001000L,0x83001040L,0x83001080L,0x830010c0L}) {
                new DisassembleCommand(toAddr(at),null,true).applyTo(currentProgram,monitor);
                if(at!=0x830010c0L)new CreateFunctionCmd(toAddr(at)).applyTo(currentProgram,monitor);
            }
        } finally {currentProgram.endTransaction(tx,true);}
        var log=new MessageLog();var analyzer=new XenonHavokAnalyzer();
        TaskMonitorAdapter cancelling=new TaskMonitorAdapter(true) {
            @Override public void checkCancelled() throws CancelledException {
                if(currentProgram.getSymbolTable().getPrimarySymbol(toAddr(0x83000000L))!=null)throw new CancelledException();
                super.checkCancelled();
            }
        };
        boolean cancelled=false;
        try {analyzer.added(currentProgram,currentProgram.getMemory(),cancelling,log);}
        catch(CancelledException expected){cancelled=true;}
        check(cancelled,"cancel inside mutation");
        check(currentProgram.getSymbolTable().getPrimarySymbol(toAddr(0x83000000L))==null,"rollback label");
        check(currentProgram.getListing().getDefinedDataAt(toAddr(0x83000000L))==null,"rollback type");
        int changes=currentProgram.startTransaction("Safety test changes");
        try {
        check(analyzer.added(currentProgram,currentProgram.getMemory(),monitor,log),"metadata pass");
        check(getFunctionAt(toAddr(0x830010c0L))!=null,"validated unowned callback recovered");
        check(!ValidatedCallbackRecovery.create(currentProgram,toAddr(0x830010c4L),monitor),"interior owner preserved");
        var tailTargetBody=new AddressSet(getFunctionAt(toAddr(0x83001000L)).getBody());
        check(ValidatedCallbackRecovery.create(currentProgram,toAddr(0x830010d0L),monitor),"unconditional tail to established entry recovered on first pass");
        check(getFunctionAt(toAddr(0x83001000L)).getBody().equals(tailTargetBody),"tail target ownership unchanged");
        check(!ValidatedCallbackRecovery.create(currentProgram,toAddr(0x830010e0L),monitor),"unresolved external branch withheld");
        check(!ValidatedCallbackRecovery.create(currentProgram,toAddr(0x830010f0L),monitor),"tail to interior owner withheld");
        int symbolCount=currentProgram.getSymbolTable().getNumSymbols();
        check(analyzer.added(currentProgram,currentProgram.getMemory(),monitor,log),"metadata repeat");
        check(symbolCount==currentProgram.getSymbolTable().getNumSymbols(),"no duplicate labels");
        check(!analyzer.added(currentProgram,new AddressSet(toAddr(0x83000000L)),monitor,log),"partial analysis deferred");
        var protectedFunction=getFunctionAt(toAddr(0x83001000L));protectedFunction.setName("user_kept_callback",SourceType.USER_DEFINED);
        var options=new ToolOptions("test");analyzer.registerOptions(options,currentProgram);
        options.setBoolean("Name validated callback functions",true);analyzer.optionsChanged(options,currentProgram);
        check(analyzer.added(currentProgram,currentProgram.getMemory(),monitor,log),"optional names");
        check(protectedFunction.getName().equals("user_kept_callback"),"preserve user callback");
        check(getFunctionAt(toAddr(0x83001040L)).getName().equals("hk_fixture_one_cleanup_loaded_object"),"unique callback name");
        var report=XenonEvidence.collect(currentProgram,true,monitor);
        var metadata=xenon360.havok.HavokMetadata.scan(XenonEvidence.snapshot(currentProgram,monitor),monitor);
        var limited=new xenon360.havok.HavokMetadata.Result(metadata.versions(),metadata.types(),metadata.classes(),
            metadata.nameStrings(),metadata.rejectedPointerCandidates(),true);
        check(XenonEvidence.functions(currentProgram,limited).stream().allMatch(row->
            row.get("status").equals("withheld_incomplete_scan") && row.get("confidence").equals("provisional")),
            "incomplete scan cannot establish class-specific callback uniqueness");
        var target=XenonEvidence.JSON.toJsonTree(report).getAsJsonObject();
        var reference=target.deepCopy();reference.getAsJsonObject("binary").addProperty("sha256","a".repeat(64));
        var comparison=CrossArchitectureMatcher.compare(reference,target,monitor);
        check(((java.util.List<?>)comparison.get("candidates")).size()==4,"BSim candidates");
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]+".comparison.json"),comparison);
        check(((java.util.List<?>)comparison.get("candidates")).stream().map(x->(Map<?,?>)x)
            .anyMatch(x->x.get("bsim_similarity") instanceof Number n && Math.abs(n.doubleValue()-1.0)<1e-9),
            "native BSim identical semantic vector");
        check(comparison.get("applied").equals(0),"comparison never applies");
        boolean bad=false;try {CrossArchitectureMatcher.compare(target,target,monitor);}catch(IllegalArgumentException expected){bad=true;}
        check(bad,"same identity rejected");
        var uppercase=target.deepCopy();uppercase.getAsJsonObject("binary").addProperty("sha256",
            uppercase.getAsJsonObject("binary").get("sha256").getAsString().toUpperCase(Locale.ROOT));
        bad=false;try {CrossArchitectureMatcher.compare(uppercase,target,monitor);}catch(IllegalArgumentException expected){bad=true;}
        check(bad,"same identity rejected regardless of hash letter case");
        var unrelated=reference.deepCopy();unrelated.add("functions",new com.google.gson.JsonArray());
        check(((java.util.List<?>)CrossArchitectureMatcher.compare(unrelated,target,monitor).get("candidates")).isEmpty(),"unrelated has no matches");
        var helper=getFunctionAt(toAddr(0x82001100L));helper.setName("user_kept_helper",SourceType.USER_DEFINED);
        var body=new AddressSet(helper.getBody());
        var helpers=new XenonCompilerHelperAnalyzer();
        check(helpers.added(currentProgram,currentProgram.getMemory(),monitor,log),"helper repeat");
        check(helper.getName().equals("user_kept_helper") && helper.getBody().equals(body),"preserve helper owner");
        check(currentProgram.getOptions("Xenon360").getInt("Helper ownership conflicts withheld",0)==1,"conflict withheld");
        var call=getInstructionAt(toAddr(0x82001004L));call.setFlowOverride(FlowOverride.CALL_RETURN);
        helpers.added(currentProgram,currentProgram.getMemory(),monitor,log);
        check(call.getFlowOverride()==FlowOverride.CALL_RETURN,"default preserves override");
        var helperOptions=new ToolOptions("helpers");helpers.registerOptions(helperOptions,currentProgram);
        helperOptions.setBoolean("Repair CALL_RETURN at exact save helpers",true);helpers.optionsChanged(helperOptions,currentProgram);
        helpers.added(currentProgram,currentProgram.getMemory(),monitor,log);
        check(call.getFlowOverride()==FlowOverride.NONE,"opt-in repair exact call");
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("result","PASS","checks",checks,"log",log.toString()));
        println("XENON_ANALYSIS_SAFETY_PASS checks="+checks);
        } finally {currentProgram.endTransaction(changes,true);}
    }
}
