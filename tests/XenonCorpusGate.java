import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import xenon360.*;
import xenon360.analysis.*;
import xenon360.havok.*;

/** Fresh import gate. Real inputs are supplied locally and never packaged. */
public class XenonCorpusGate extends HeadlessScript {
    private Map<String,Object> census() throws Exception {
        MessageDigest functions=MessageDigest.getInstance("SHA-256"),calls=MessageDigest.getInstance("SHA-256");
        int count=0,helpers=0,callCount=0,overrides=0;
        var it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {
            monitor.checkCancelled();var f=it.next();count++;
            if("xenon_ppc_savegpr_noop".equals(f.getCallFixup()))helpers++;
            functions.update((f.getEntryPoint()+"|"+f.getName()+"|"+f.getBody()+"|"+f.getCallFixup()+"\n").getBytes(StandardCharsets.UTF_8));
        }
        var instructions=currentProgram.getListing().getInstructions(true);
        while(instructions.hasNext()) {
            monitor.checkCancelled();var i=instructions.next();
            if(i.getFlowOverride()==FlowOverride.CALL_RETURN)overrides++;
            for(var ref:i.getReferencesFrom())if(ref.getReferenceType().isCall()) {
                callCount++;calls.update((ref.getFromAddress()+"|"+ref.getToAddress()+"|"+ref.getReferenceType()+"\n").getBytes(StandardCharsets.UTF_8));
            }
        }
        return Map.of("functions",count,"helpers",helpers,"calls",callCount,"call_return_overrides",overrides,
            "function_digest",HexFormat.of().formatHex(functions.digest()),"call_graph_digest",HexFormat.of().formatHex(calls.digest()),
            "error_bookmarks",currentProgram.getBookmarkManager().getBookmarkCount("Error"));
    }
    @Override protected void run() throws Exception {
        Path output=Path.of(getScriptArgs()[0]);Files.createDirectories(output);
        if(analysisTimeoutOccurred()) {
            XenonEvidence.writeAtomic(output.resolve("gate.json"),Map.of("result","FAIL_TIMEOUT",
                "partial_census",census(),"binary_sha256",XenonEvidence.sourceHash(currentProgram)));
            println("XENON_CORPUS_GATE_FAIL_TIMEOUT: partial project retained for diagnosis");return;
        }
        boolean xenon=currentProgram.getLanguageID().toString().contains("Xenon");
        if(!xenon) {
            // Deliberately bounded PC analysis of validated callbacks in a fresh, disposable import.
            var metadata=HavokMetadata.scan(XenonEvidence.snapshot(currentProgram,monitor),monitor);
            int tx=currentProgram.startTransaction("Validated PC callback fixtures");boolean commit=false;
            try {
                for(var type:metadata.types())for(long value:new long[]{type.finish(),type.cleanup()}) {
                    if(value==0)continue;Address a=toAddr(value);
                    if(currentProgram.getFunctionManager().getFunctionContaining(a)!=null)continue;
                    new DisassembleCommand(a,null,true).applyTo(currentProgram,monitor);
                    new CreateFunctionCmd(a).applyTo(currentProgram,monitor);
                }
                commit=true;
            } finally {currentProgram.endTransaction(tx,commit);}
        }
        var before=census();var log=new MessageLog();
        Map<String,Object> gate=new LinkedHashMap<>();gate.put("binary_sha256",XenonEvidence.sourceHash(currentProgram));
        gate.put("before",before);
        if(xenon) {
            var info=currentProgram.getOptions("Xenon360");
            gate.put("automatic_havok_ran",info.contains("Havok validated type info"));
            if(!info.contains("Havok validated type info"))throw new AssertionError("Automatic Havok analyzer did not run");
            gate.put("automatic_switch_ran",info.contains("Switch analysis summary"));
            if(!info.contains("Switch analysis summary"))throw new AssertionError("Automatic switch analyzer did not run");
            for(int pass=0;pass<2;pass++) {
                if(!new XenonCompilerHelperAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError("Helper pass failed");
                if(!new XenonHavokAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError("Havok pass failed");
                if(!new XenonSwitchAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError("Switch pass failed");
                if(!before.equals(census())) {
                    gate.put("after",census());gate.put("result","FAIL_IDEMPOTENCY");gate.put("failed_pass",pass);
                    XenonEvidence.writeAtomic(output.resolve("gate.json"),gate);
                    XenonEvidence.writeAtomic(output.resolve("evidence.json"),XenonEvidence.collect(currentProgram,false,monitor));
                    println("XENON_CORPUS_GATE_FAIL_IDEMPOTENCY: partial project retained for diagnosis");return;
                }
            }
        }
        var report=XenonEvidence.collect(currentProgram,true,monitor);
        XenonEvidence.writeAtomic(output.resolve("evidence.json"),report);
        gate.put("after",census());gate.put("reanalyze_log",log.toString());gate.put("result","PASS");
        gate.put("scan",report.get("scan"));gate.put("pc_analysis",xenon?"not_applicable":"bounded validated callbacks; no whole-program analysis");
        XenonEvidence.writeAtomic(output.resolve("gate.json"),gate);
        println("XENON_CORPUS_GATE_PASS "+XenonEvidence.JSON.toJson(gate));
    }
}
