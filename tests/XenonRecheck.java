import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.decompiler.DecompInterface;
import java.nio.file.*;
import java.util.*;
import xenon360.*;
import xenon360.analysis.*;

/** Recheck a disposable full-analysis project with a later candidate; preserve old evidence. */
public class XenonRecheck extends HeadlessScript {
    private Map<String,String> bodies() {
        Map<String,String> result=new TreeMap<>();var it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {var f=it.next();result.put(f.getEntryPoint().toString(),f.getName()+"|"+f.getBody());}
        return result;
    }
    @Override protected void run() throws Exception {
        Path output=Path.of(getScriptArgs()[0]);Files.createDirectories(output);
        var before=bodies();var log=new MessageLog();
        if(currentProgram.getLanguageID().toString().contains("Xenon")) {
            if(!new XenonCompilerHelperAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError(log);
            if(!new XenonHavokAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError(log);
            if(!new XenonSwitchAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError(log);
            analyzeChanges(currentProgram);
        }
        var after=bodies();var changed=new ArrayList<String>();
        before.forEach((at,body)->{if(!body.equals(after.get(at)))changed.add(at);});
        var added=new TreeMap<>(after);before.keySet().forEach(added::remove);
        XenonEvidence.writeAtomic(output.resolve("recovery.json"),Map.of("existing_functions_changed",changed,
            "added_functions",added,"log",log.toString(),"before_count",before.size(),"after_count",after.size()));
        if(!changed.isEmpty())throw new AssertionError("Established function boundaries/names changed: "+changed);
        runScript("XenonCorpusGate.java",new String[]{output.toString()});
        XenonEvidence.writeAtomic(output.resolve("boundaries.json"),after);
        var report=XenonEvidence.collect(currentProgram,false,monitor);
        @SuppressWarnings("unchecked") var rows=(List<Map<String,Object>>)report.get("functions");
        List<Map<String,Object>> audit=new ArrayList<>();var decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(currentProgram))throw new AssertionError(decompiler.getLastMessage());
            for(var row:rows) {
                monitor.checkCancelled();var at=currentProgram.getAddressFactory().getAddress((String)row.get("address"));
                var f=currentProgram.getFunctionManager().getFunctionAt(at);if(f==null)continue;
                List<String> instructions=new ArrayList<>();var it=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(it.hasNext() && instructions.size()<64) {var i=it.next();instructions.add(i.getAddress()+" "+HexFormat.of().formatHex(i.getBytes())+" "+i);}
                var result=decompiler.decompileFunction(f,10,monitor);
                Map<String,Object> item=new LinkedHashMap<>();item.put("address",row.get("address"));item.put("recommended_name",row.get("recommended_name"));
                item.put("binary_sha256",row.get("binary_sha256"));item.put("instructions",instructions);item.put("body",f.getBody().toString());
                item.put("decompile_completed",result.decompileCompleted());item.put("error",result.getErrorMessage());
                item.put("decompiled",result.getDecompiledFunction()==null?null:result.getDecompiledFunction().getC());audit.add(item);
            }
        } finally {decompiler.dispose();}
        XenonEvidence.writeAtomic(output.resolve("callback-audit.json"),audit);
        println("XENON_RECHECK_PASS established_functions_preserved="+before.size()+" added="+added.size());
    }
}
