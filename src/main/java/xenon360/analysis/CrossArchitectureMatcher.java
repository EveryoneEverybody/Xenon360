package xenon360.analysis;

import java.util.*;
import com.google.gson.*;
import generic.lsh.vector.*;
import ghidra.framework.Application;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlPullParserFactory;
import org.xml.sax.helpers.DefaultHandler;

/** Class/role anchors nominate candidates; native BSim features only corroborate them. */
public final class CrossArchitectureMatcher {
    private CrossArchitectureMatcher() {}
    private static JsonObject validate(JsonObject document) {
        try {
        if(!document.has("schema") || !XenonEvidence.SCHEMA.equals(document.get("schema").getAsString()))
            throw new IllegalArgumentException("Select a Xenon360 analysis evidence JSON export");
        String hash=document.getAsJsonObject("binary").get("sha256").getAsString();
        if(!hash.matches("[0-9a-fA-F]{64}")) throw new IllegalArgumentException("Reference binary SHA-256 is missing");
        if(document.get("signature_settings").getAsInt()!=XenonEvidence.SIGNATURE_SETTINGS)
            throw new IllegalArgumentException("Incompatible BSim signature settings; re-export both programs");
        if(document.getAsJsonArray("functions").size()>10000) throw new IllegalArgumentException("Reference function limit exceeded");
        return document;
        } catch(NullPointerException | IllegalStateException | UnsupportedOperationException ex) {
            throw new IllegalArgumentException("Incomplete or malformed Xenon360 evidence; export the reference again",ex);
        }
    }
    private static Map<String,JsonObject> uniqueAnchors(JsonObject report) {
        Map<String,JsonObject> result=new TreeMap<>(); Set<String> duplicate=new HashSet<>();
        for(var element:report.getAsJsonArray("functions")) {
            var row=element.getAsJsonObject();
            if(!"high".equals(row.get("confidence").getAsString())) continue;
            for(var anchor:row.getAsJsonArray("evidence")) {
                var a=anchor.getAsJsonObject();
                String key=a.get("class_name").getAsString()+"/"+a.get("role").getAsString();
                var prior=result.putIfAbsent(key,row);
                if(prior!=null && !prior.get("address").equals(row.get("address"))) duplicate.add(key);
            }
        }
        duplicate.forEach(result::remove); return result;
    }
    public static Map<String,Object> compare(JsonObject reference,JsonObject target,TaskMonitor monitor) throws Exception {
        validate(reference); validate(target);
        if(reference.getAsJsonObject("binary").get("sha256").getAsString().equalsIgnoreCase(
            target.getAsJsonObject("binary").get("sha256").getAsString()))
            throw new IllegalArgumentException("Comparison requires two independently identified binaries");
        var left=uniqueAnchors(reference);var right=uniqueAnchors(target);
        var factory=new WeightedLSHCosineVectorFactory();
        var weights=Application.getModuleDataFile("BSim","lshweights_nosize.xml");
        var parser=XmlPullParserFactory.create(weights,new DefaultHandler(),false);
        try {factory.readWeights(parser);} finally {parser.dispose();}
        List<Map<String,Object>> candidates=new ArrayList<>(); Set<String> addresses=new HashSet<>();
        for(var entry:right.entrySet()) {
            monitor.checkCancelled();
            var a=left.get(entry.getKey()); if(a==null) continue; var b=entry.getValue();
            // One proposed name and one candidate per target address, even with duplicate descriptors.
            if(!addresses.add(b.get("address").getAsString())) continue;
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("reference_binary_sha256",reference.getAsJsonObject("binary").get("sha256").getAsString());
            row.put("binary_sha256",target.getAsJsonObject("binary").get("sha256").getAsString());
            row.put("reference_address",a.get("address").getAsString());row.put("address",b.get("address").getAsString());
            row.put("recommended_name",b.get("recommended_name").getAsString());
            row.put("identification_source","independently validated hkTypeInfo class/role anchors; native Ghidra BSim corroboration");
            row.put("sdk_version",b.get("sdk_version").getAsString());
            row.put("anchor",entry.getKey());row.put("status","withheld_requires_review");
            row.put("confidence","provisional");
            if(complete(a)&&complete(b)) {
                var va=factory.buildVector(features(a));var vb=factory.buildVector(features(b));
                if(va.getLength()>0 && vb.getLength()>0) {
                    var details=new VectorCompare();double similarity=va.compare(vb,details);
                    details.fillOut();double significance=factory.calculateSignificance(details);
                    row.put("bsim_similarity",similarity);row.put("bsim_significance",significance);
                    row.put("bsim_shared_features",details.intersectcount);
                    if(similarity>=0.8 && significance>=10) row.put("confidence","corroborated_candidate");
                } else row.put("bsim_status","empty_features");
            } else row.put("bsim_status","unavailable_or_partial");
            row.put("evidence",List.of("matching retained class identity and callback role",
                "independent target metadata validation", "ABI and object layout remain target-specific"));
            candidates.add(row);
        }
        return Map.of("schema","xenon360/cross-architecture-v1","reference",reference.get("binary"),"target",target.get("binary"),
            "weights","Ghidra " + Application.getApplicationVersion() + " BSim lshweights_nosize.xml","signature_settings",XenonEvidence.SIGNATURE_SETTINGS,
            "candidates",candidates,"applied",0,"policy","Similarity is supporting evidence, never an automatic name or ABI transfer.");
    }
    private static boolean complete(JsonObject row) {
        return row.has("bsim_features") && row.has("bsim_status") && "complete".equals(row.get("bsim_status").getAsString());
    }
    private static int[] features(JsonObject row) {
        JsonArray array=row.getAsJsonArray("bsim_features");
        if(array.size()>100000) throw new IllegalArgumentException("Reference feature limit exceeded");
        int[] result=new int[array.size()];for(int i=0;i<result.length;i++)result[i]=array.get(i).getAsInt();
        Arrays.sort(result);return result;
    }
}
