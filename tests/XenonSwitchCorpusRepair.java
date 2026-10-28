import ghidra.app.util.headless.HeadlessScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSet;
import java.nio.file.*;
import java.util.*;
import xenon360.XenonSwitchAnalyzer;
import xenon360.analysis.XenonEvidence;

/** Validate a targeted switch repair on a copy, retaining every existing owned byte/name. */
public class XenonSwitchCorpusRepair extends HeadlessScript {
    @Override protected void run() throws Exception {
        Path output=Path.of(getScriptArgs()[0]);Files.createDirectories(output);
        var names=new TreeMap<String,String>();var bodies=new TreeMap<String,AddressSet>();
        var it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()){var f=it.next();var at=f.getEntryPoint().toString();names.put(at,f.getName());bodies.put(at,new AddressSet(f.getBody()));}
        var log=new MessageLog();if(!new XenonSwitchAnalyzer().added(currentProgram,currentProgram.getMemory(),monitor,log))throw new AssertionError(log);
        analyzeChanges(currentProgram);
        var expanded=new TreeMap<String,Object>();
        for(var e:bodies.entrySet()) {
            var f=getFunctionAt(toAddr(e.getKey()));
            if(f==null || !f.getName().equals(names.get(e.getKey())) || !f.getBody().contains(e.getValue()))throw new AssertionError("Established owner/name lost at "+e.getKey());
            if(!f.getBody().equals(e.getValue()))expanded.put(e.getKey(),Map.of("before",e.getValue().toString(),"after",f.getBody().toString()));
        }
        XenonEvidence.writeAtomic(output.resolve("switch-repair.json"),Map.of("result","PASS","existing_functions",names.size(),
            "existing_owned_bytes_removed",0,"existing_names_changed",0,"expanded_bodies",expanded,"log",log.toString()));
        runScript("XenonRecheck.java",new String[]{output.toString()});
    }
}
