import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import com.google.gson.JsonParser;
import xenon360.analysis.*;
public class XenonCompareEvidence extends GhidraScript {
    @Override protected void run() throws Exception {
        var args=getScriptArgs();
        var left=JsonParser.parseString(Files.readString(Path.of(args[0]))).getAsJsonObject();
        var right=JsonParser.parseString(Files.readString(Path.of(args[1]))).getAsJsonObject();
        var report=CrossArchitectureMatcher.compare(left,right,monitor);
        XenonEvidence.writeAtomic(Path.of(args[2]),report);
        println("XENON_COMPARISON_EXPORTED candidates="+((java.util.List<?>)report.get("candidates")).size());
    }
}
