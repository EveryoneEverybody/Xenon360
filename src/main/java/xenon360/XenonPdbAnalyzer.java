package xenon360;

import java.io.IOException;
import java.nio.file.Path;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.xex.XexImage;

public final class XenonPdbAnalyzer extends AbstractAnalyzer {
    public static final String NAME = "Xenon360 PDB/XDB";
    private static final String DESCRIPTION =
        "Applies loader-validated Xbox 360 PDB/XDB symbols through Ghidra PDB Universal.";

    public XenonPdbAnalyzer() {
        super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.after());
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        if (!XenonXexLoader.FORMAT_NAME.equals(program.getExecutableFormat())) return false;
        Options x = program.getOptions("Xenon360");
        String path = x.getString("Symbol file path", "");
        return !path.isBlank()
            && x.getBoolean("Symbol identity verified", false)
            && !x.getBoolean("Symbol main application", false);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
            throws CancelledException {
        if (!set.contains(program.getMemory())) return false;
        Options x = program.getOptions("Xenon360");
        String symbolPath = x.getString("Symbol file path", "");
        String guid = x.getString("CodeView GUID", "");
        long age = x.getLong("CodeView age", -1);
        String codeViewPath = x.getString("CodeView PDB path", "");
        String expectedSha = x.getString("Symbol SHA-256", "");
        String mode = x.getString("Symbol processing mode", "public-symbols");

        if (symbolPath.isBlank() || guid.isBlank() || age < 0 || expectedSha.isBlank()) {
            log.appendMsg(NAME, "Validated symbol metadata is incomplete; not applying symbols.");
            return false;
        }

        try {
            Path path = Path.of(symbolPath);
            XexImage.CodeViewInfo codeView =
                new XexImage.CodeViewInfo("RSDS", guid, age, codeViewPath);
            XenonPdbSupport.Info info = XenonPdbSupport.validate(path, codeView, monitor);
            if (!info.sha256().equalsIgnoreCase(expectedSha)) {
                x.setBoolean("Symbol identity verified", false);
                log.appendMsg(NAME, "Symbol file changed after import validation; SHA-256 mismatch.");
                return false;
            }

            monitor.setMessage("Xenon360: applying validated " + info.kind() + " (" + mode + ")");
            if (!XenonPdbSupport.apply(program, path, mode, log, monitor)) {
                log.appendMsg(NAME, "Ghidra PDB Universal reported failure.");
                return false;
            }
            x.setBoolean("Symbol main application", true);
            log.appendMsg(NAME, "XENON_SYMBOL_APPLICATION_PASS"
                + ";kind=" + info.kind()
                + ";sha256=" + info.sha256()
                + ";guid=" + info.guid()
                + ";age=" + Integer.toUnsignedLong(info.age())
                + ";processor=" + info.processor()
                + ";mode=" + mode);
            return true;
        }
        catch (IOException | RuntimeException ex) {
            log.appendException(ex);
            log.appendMsg(NAME, "Symbol application rejected: " + ex.getMessage());
            return false;
        }
    }
}
