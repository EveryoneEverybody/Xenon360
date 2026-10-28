import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.listing.FlowOverride;
import java.nio.file.*;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.GsonBuilder;

/** Version-neutral full-analysis census for the preserved v07 package. */
public class XenonBaselineCensus extends HeadlessScript {
    @Override protected void run() throws Exception {
        MessageDigest functions=MessageDigest.getInstance("SHA-256"),calls=MessageDigest.getInstance("SHA-256");
        int count=0,helpers=0,callCount=0,overrides=0;
        List<Map<String,Object>> boundaries=new ArrayList<>();
        var it=currentProgram.getFunctionManager().getFunctions(true);
        while(it.hasNext()) {
            monitor.checkCancelled();var f=it.next();count++;
            if("xenon_ppc_savegpr_noop".equals(f.getCallFixup()))helpers++;
            functions.update((f.getEntryPoint()+"|"+f.getName()+"|"+f.getBody()+"|"+f.getCallFixup()+"\n").getBytes(StandardCharsets.UTF_8));
            boundaries.add(Map.of("address",f.getEntryPoint().toString(),"name",f.getName(),"body",f.getBody().toString()));
        }
        var instructions=currentProgram.getListing().getInstructions(true);
        while(instructions.hasNext()) {
            monitor.checkCancelled();var i=instructions.next();
            if(i.getFlowOverride()==FlowOverride.CALL_RETURN)overrides++;
            for(var ref:i.getReferencesFrom())if(ref.getReferenceType().isCall()) {
                callCount++;calls.update((ref.getFromAddress()+"|"+ref.getToAddress()+"|"+ref.getReferenceType()+"\n").getBytes(StandardCharsets.UTF_8));
            }
        }
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("functions",count);result.put("helpers",helpers);result.put("calls",callCount);result.put("call_return_overrides",overrides);
        result.put("function_digest",HexFormat.of().formatHex(functions.digest()));result.put("call_graph_digest",HexFormat.of().formatHex(calls.digest()));
        result.put("error_bookmarks",currentProgram.getBookmarkManager().getBookmarkCount("Error"));
        result.put("result",analysisTimeoutOccurred()?"FAIL_TIMEOUT":"PASS");
        result.put("binary_sha256",currentProgram.getOptions("Xenon360").getString("Source SHA-256",currentProgram.getExecutableSHA256()));
        var json=new GsonBuilder().setPrettyPrinting().create();Path output=Path.of(getScriptArgs()[0]);Files.createDirectories(output);
        Files.writeString(output.resolve("gate.json"),json.toJson(result));Files.writeString(output.resolve("boundaries.json"),json.toJson(boundaries));
        println("XENON_BASELINE_CENSUS_"+result.get("result")+" "+json.toJson(result));
    }
}
