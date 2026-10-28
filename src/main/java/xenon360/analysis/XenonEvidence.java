package xenon360.analysis;

import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.havok.HavokMetadata;

/** Deterministic evidence shared by analyzers, GUI export, and headless tests. */
public final class XenonEvidence {
    public static final Gson JSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    public static final String SCHEMA = "xenon360/analysis-evidence-v1";
    // Ghidra's stock medium_nosize / lshweights_nosize profile, for pointer-width changes.
    public static final int SIGNATURE_SETTINGS = 0x4d;
    private XenonEvidence() {}

    public static BinaryImage snapshot(Program program, TaskMonitor monitor)
            throws MemoryAccessException, CancelledException {
        List<BinaryImage.Segment> segments = new ArrayList<>();
        List<BinaryImage.Mapping> mappings = new ArrayList<>();
        long total = 0;
        for (var block : program.getMemory().getBlocks()) {
            if(!block.isOverlay()) mappings.add(new BinaryImage.Mapping(block.getStart().getOffset(),block.getSize()));
            if (!block.isInitialized() || block.isOverlay()) continue;
            monitor.checkCancelled();
            total += block.getSize();
            if (block.getSize() > 256L * 1024 * 1024 || total > 512L * 1024 * 1024) {
                throw new IllegalArgumentException("Havok scan is bounded to 256 MiB per block and 512 MiB total");
            }
            byte[] bytes = new byte[(int)block.getSize()];
            for (int offset = 0; offset < bytes.length; offset += 65536) {
                monitor.checkCancelled();
                int length = Math.min(65536, bytes.length - offset);
                if (block.getBytes(block.getStart().add(offset), bytes, offset, length) != length) {
                    throw new MemoryAccessException("Incomplete memory read at " + block.getStart());
                }
            }
            segments.add(new BinaryImage.Segment(block.getStart().getOffset(), bytes, block.isExecute()));
        }
        return new BinaryImage(segments, mappings, program.getDefaultPointerSize(), program.getLanguage().isBigEndian(),
            program.getLanguage().getProcessor().toString().equals("PowerPC"));
    }

    public static String sourceHash(Program p) {
        String hash = p.getOptions("Xenon360").getString("Source SHA-256", p.getExecutableSHA256());
        return hash == null || !hash.matches("(?i)[0-9a-f]{64}") ? "UNKNOWN" : hash.toLowerCase(Locale.ROOT);
    }

    public static Map<String, Object> collect(Program program, boolean signatures, TaskMonitor monitor)
            throws Exception {
        monitor.setMessage("Xenon360: validating Havok metadata");
        var result = HavokMetadata.scan(snapshot(program, monitor), monitor);
        Map<String, Object> report = new LinkedHashMap<>();
        report.put("schema", SCHEMA);
        report.put("extension_version", xenon360.xex.XexImage.VERSION);
        report.put("binary", Map.of("name",program.getName(),"sha256",sourceHash(program),
            "language",program.getLanguageID().toString(),"image_base",program.getImageBase().toString(),
            "compiler",program.getCompilerSpec().getCompilerSpecID().toString(),
            "pointer_bytes",program.getDefaultPointerSize(),"big_endian",program.getLanguage().isBigEndian()));
        report.put("havok_versions", result.versions());
        report.put("version_policy", "Version markers identify retained metadata; no exact linked SDK build is inferred from layout alone.");
        report.put("scan", Map.of("name_strings",result.nameStrings(),"rejected_pointer_candidates",result.rejectedPointerCandidates(),
            "limited",result.limited(),"validated_type_info",result.types().size(),"validated_hk_class",result.classes().size()));
        List<Map<String, Object>> types = new ArrayList<>();
        for (var type : result.types()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("address",BinaryImage.address(type.address())); row.put("class_name",type.className());
            row.put("layout_profile",type.profile()); row.put("object_size",type.objectSize()<0?null:type.objectSize());
            row.put("finish",BinaryImage.address(type.finish())); row.put("cleanup",BinaryImage.address(type.cleanup()));
            row.put("vtable",BinaryImage.address(type.vtable())); row.put("evidence",type.evidence());
            row.put("status","validated_structure"); types.add(row);
        }
        report.put("havok_type_info",types);
        report.put("havok_classes",result.classes());
        List<Map<String, Object>> functions = functions(program,result);
        report.put("functions",functions);
        if (signatures) addSignatures(program, functions, monitor);
        String imports = program.getOptions("Xenon360").getString("Import evidence JSON", "[]");
        report.put("imports",JsonParser.parseString(imports));
        var options=program.getOptions("Xenon360");
        report.put("switch_tables",JsonParser.parseString(options.getString("Switch evidence JSON","[]")));
        report.put("analysis_summaries",Map.of("compiler_helpers",options.getString("Helper analysis summary","not_run"),
            "bounded_switches",options.getString("Switch analysis summary","not_run"),
            "switch_scan_limited",options.getBoolean("Switch scan limited",false)));
        report.put("signature_settings",SIGNATURE_SETTINGS);
        report.put("limitations",List.of("No cross-architecture prototypes or instance layouts are copied.",
            "Unobserved Havok function families remain unidentified.",
            "Metadata validation is not game execution or user validation."));
        return report;
    }

    public static List<Map<String, Object>> functions(Program p, HavokMetadata.Result metadata) {
        Map<Long, List<Map<String, Object>>> byAddress = new TreeMap<>();
        for (var type : metadata.types()) {
            for (String role : List.of("finish_loaded_object","cleanup_loaded_object")) {
                long at = role.startsWith("finish") ? type.finish() : type.cleanup();
                if (at == 0) continue;
                byAddress.computeIfAbsent(at,k->new ArrayList<>()).add(Map.of("class_name",type.className(),
                    "role",role,"descriptor",BinaryImage.address(type.address()),"profile",type.profile(),"evidence",type.evidence()));
            }
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        String versions = metadata.versions().stream().map(HavokMetadata.Version::marker).distinct().sorted()
            .reduce((a,b)->a+";"+b).orElse("UNKNOWN");
        for (var entry : byAddress.entrySet()) {
            var anchors = entry.getValue();
            Set<String> names = new TreeSet<>();
            for(var a:anchors) names.add(HavokMetadata.snake((String)a.get("class_name"))+"_"+a.get("role"));
            boolean shared = names.size()!=1;
            String name = shared ? "havok_shared_loaded_object_callback" : names.iterator().next();
            Function f=p.getFunctionManager().getFunctionAt(p.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey()));
            String owned=p.getOptions("Xenon360").getString("Havok applied name "+BinaryImage.address(entry.getKey()),"");
            String status = shared ? "withheld_shared_callback" : f==null ? "withheld_function_boundary" :
                f.getName().equals(owned)&&owned.equals(name) ? "applied" :
                f.getSymbol().getSource()!=ghidra.program.model.symbol.SourceType.DEFAULT ? "withheld_existing_symbol" : "withheld_auto_rename_disabled";
            // A truncated scan cannot establish that a callback is unique to one
            // class. Keep its evidence, but never permit automatic recovery/naming.
            if(metadata.limited()) status="withheld_incomplete_scan";
            if(sourceHash(p).equals("UNKNOWN")) status="withheld_binary_identity";
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("binary_sha256",sourceHash(p)); row.put("address",BinaryImage.address(entry.getKey()));
            row.put("recommended_name",name); row.put("observed_name",f==null?null:f.getName());
            row.put("identification_source","validated hkTypeInfo callback slot"); row.put("sdk_version",versions);
            row.put("evidence",anchors); row.put("confidence",shared||metadata.limited()?"provisional":"high"); row.put("status",status);
            rows.add(row);
        }
        return rows;
    }

    private static void addSignatures(Program p, List<Map<String,Object>> functions, TaskMonitor monitor)
            throws CancelledException {
        DecompInterface decompiler=new DecompInterface();
        try {
            if(!decompiler.openProgram(p)) throw new IllegalStateException("Native decompiler: "+decompiler.getLastMessage());
            if(!decompiler.setSignatureSettings(SIGNATURE_SETTINGS)) throw new IllegalStateException("Cannot configure BSim signature extraction");
            int count=0;
            for(var row:functions) {
                monitor.checkCancelled();
                if(++count>256) {row.put("bsim_status","withheld_function_limit");continue;}
                Function f=p.getFunctionManager().getFunctionAt(p.getAddressFactory().getAddress((String)row.get("address")));
                if(f==null || f.isThunk()) {row.put("bsim_status","withheld_missing_function_or_thunk");continue;}
                monitor.setMessage("Xenon360: BSim features "+count+"/"+functions.size());
                var signature=decompiler.generateSignatures(f,true,5,monitor);
                monitor.checkCancelled();
                if(signature==null) {row.put("bsim_status","unavailable");row.put("bsim_error",decompiler.getLastMessage());continue;}
                row.put("bsim_status",signature.hasbaddata||signature.hasunimplemented?"partial":"complete");
                row.put("bsim_features",signature.features);
                row.put("calls",signature.calllist.stream().map(Object::toString).toList());
            }
        } finally {decompiler.dispose();}
    }

    public static void writeAtomic(Path file, Object report) throws IOException {
        Path absolute=file.toAbsolutePath();
        Path tmp=Files.createTempFile(absolute.getParent(),"xenon-evidence-",".tmp");
        try {
            Files.writeString(tmp,JSON.toJson(canonical(JSON.toJsonTree(report)))+"\n");
            try {Files.move(tmp,absolute,StandardCopyOption.REPLACE_EXISTING,StandardCopyOption.ATOMIC_MOVE);}
            catch(AtomicMoveNotSupportedException ex) {Files.move(tmp,absolute,StandardCopyOption.REPLACE_EXISTING);}
        } finally {Files.deleteIfExists(tmp);}
    }
    private static JsonElement canonical(JsonElement value) {
        if(value.isJsonObject()) {
            var result=new JsonObject();
            for(String key:new TreeSet<>(value.getAsJsonObject().keySet()))result.add(key,canonical(value.getAsJsonObject().get(key)));
            return result;
        }
        if(value.isJsonArray()) {
            var result=new JsonArray();for(var item:value.getAsJsonArray())result.add(canonical(item));return result;
        }
        return value;
    }
}
