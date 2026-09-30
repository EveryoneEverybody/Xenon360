package xenon360;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.HexFormat;

import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.util.bin.format.pdb2.pdbreader.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorControl;
import ghidra.app.util.pdb.pdbapplicator.DefaultPdbApplicator;
import ghidra.app.util.pdb.pdbapplicator.PdbApplicatorOptions;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.xex.XexImage;

final class XenonPdbSupport {
    static final long MAX_SYMBOL_BYTES = 512L * 1024 * 1024;

    record Info(String kind, String sha256, int version, int signature, int age,
                String guid, String processor, boolean deserialized) { }

    private XenonPdbSupport() { }

    static Info inspect(Path path, boolean fullDeserialize, TaskMonitor monitor)
            throws IOException, CancelledException {
        if (!Files.isRegularFile(path))
            throw new IOException("Symbol path is not a file: " + path);
        long size = Files.size(path);
        if (size <= 0 || size > MAX_SYMBOL_BYTES)
            throw new IOException("Symbol file exceeds 512 MiB limit or is empty");
        String lower = path.getFileName().toString().toLowerCase();
        String kind = lower.endsWith(".pdb") ? "PDB" : lower.endsWith(".xdb") ? "XDB" : null;
        if (kind == null) throw new IOException("Symbol file must end in .pdb or .xdb");

        try (AbstractPdb pdb = PdbParser.parse(path.toFile(), new PdbReaderOptions(), monitor)) {
            PdbIdentifiers id = pdb.getIdentifiers();
            if (fullDeserialize) pdb.deserialize();
            String guid = id.getGuid() == null ? null : id.getGuid().toString().toLowerCase();
            return new Info(kind, sha256(path), id.getVersion(), id.getSignature(), id.getAge(),
                guid, pdb.getTargetProcessor().toString(), pdb.isDeserialized());
        }
        catch (PdbException ex) {
            throw new IOException("Ghidra PDB parser rejected symbol file: " + ex.getMessage(), ex);
        }
    }

    static Info validate(Path path, XexImage.CodeViewInfo codeView, TaskMonitor monitor)
            throws IOException, CancelledException {
        if (codeView == null)
            throw new IOException("Selected symbol file cannot be identity-checked: XEX has no RSDS CodeView record");
        if (!"RSDS".equals(codeView.signature()))
            throw new IOException("Selected symbol file requires RSDS CodeView identity");
        Info info = inspect(path, false, monitor);
        if (info.guid() == null)
            throw new IOException("Selected symbol file has no GUID");
        if (!info.guid().equalsIgnoreCase(codeView.guid()))
            throw new IOException("Symbol GUID mismatch: XEX=" + codeView.guid() + " symbol=" + info.guid());
        if (Integer.toUnsignedLong(info.age()) != codeView.age())
            throw new IOException("Symbol age mismatch: XEX=" + codeView.age()
                + " symbol=" + Integer.toUnsignedLong(info.age()));
        String processor = info.processor().toLowerCase();
        if (!processor.contains("ppc") || !processor.contains("big endian"))
            throw new IOException("Symbol target is not PPC big-endian: " + info.processor());
        return info;
    }

    static boolean apply(Program program, Path path, String mode, MessageLog log,
            TaskMonitor monitor) throws CancelledException {
        PdbApplicatorOptions options = new PdbApplicatorOptions();
        if ("public-symbols".equals(mode)) {
            options.setProcessingControl(PdbApplicatorControl.PUBLIC_SYMBOLS_ONLY);
            options.setApplyFunctionVariables(false);
            options.setApplySourceLineNumbers(false);
            PdbReaderOptions readerOptions = new PdbReaderOptions();
            try (AbstractPdb pdb = PdbParser.parse(path.toFile(), readerOptions, monitor)) {
                monitor.setMessage("Xenon360: parsing validated " + path.getFileName());
                pdb.deserialize();
                DefaultPdbApplicator applicator = new DefaultPdbApplicator(
                    pdb, program, program.getDataTypeManager(), program.getImageBase(),
                    options, monitor, log);
                applicator.applyDataTypesAndMainSymbolsAnalysis();
                DefaultPdbApplicator.applyAnalysisReporting(program);
                return true;
            }
            catch (PdbException | IOException ex) {
                log.appendMsg("Xenon360 PDB/XDB",
                    "Public-symbol application failed for " + path + ": " + ex);
                return false;
            }
        }
        if ("all".equals(mode)) {
            options.setProcessingControl(PdbApplicatorControl.ALL);
            return PdbUniversalAnalyzer.doAnalysis(program, path.toFile(),
                new PdbReaderOptions(), options, log, monitor);
        }
        throw new IllegalArgumentException("Unsupported PDB/XDB processing mode: " + mode);
    }

    private static String sha256(Path path) throws IOException {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            try (InputStream in = Files.newInputStream(path)) {
                byte[] buffer = new byte[1 << 20];
                for (int n; (n = in.read(buffer)) >= 0; ) {
                    if (n != 0) md.update(buffer, 0, n);
                }
            }
            return HexFormat.of().formatHex(md.digest());
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
