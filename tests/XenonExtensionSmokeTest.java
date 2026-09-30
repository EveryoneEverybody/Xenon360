import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.listing.FlowOverride;
import java.nio.file.Files;
import java.nio.file.Path;

/** Validates a fresh synthetic import without applying repair operations. */
public class XenonExtensionSmokeTest extends GhidraScript {
    @Override
    protected void run() throws Exception {
        if (!currentProgram.getLanguageID().toString().equals("PowerPC:BE:64:Xenon-VMX128-32addr")) {
            throw new IllegalStateException("The import did not use the Xenon language.");
        }
        int helpers = 0;
        var functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            var function = functions.next();
            if ("xenon_ppc_savegpr_noop".equals(function.getCallFixup())) {
                if (function.hasNoReturn()) { throw new IllegalStateException("Save helper is non-returning."); }
                helpers++;
            }
        }
        if (helpers != 16) { throw new IllegalStateException("Expected 16 modeled helper entries, got " + helpers); }
        var call = currentProgram.getListing().getInstructionAt(toAddr(0x82001004L));
        if (call == null || call.getFlowOverride() == FlowOverride.CALL_RETURN) {
            throw new IllegalStateException("The helper call incorrectly terminates its caller.");
        }
        if (currentProgram.getListing().getInstructionAt(toAddr(0x82001008L)) == null) {
            throw new IllegalStateException("The caller continuation was not analyzed.");
        }
        var decoder = new PseudoDisassembler(currentProgram);
        String[] expected = {"vnmsubfp128", "vandc128", "vcmpbfp128"};
        for (int i = 0; i < expected.length; i++) {
            var instruction = decoder.disassemble(toAddr(0x82001200L + 4L * i));
            if (instruction == null || !expected[i].equals(instruction.getMnemonicString())) {
                throw new IllegalStateException("Incorrect VMX128 decoding: " + expected[i]);
            }
        }
        var decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new IllegalStateException("Could not initialize the native decompiler.");
            }
            var function = currentProgram.getFunctionManager().getFunctionAt(toAddr(0x82001000L));
            var result = decompiler.decompileFunction(function, 30, monitor);
            if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                throw new IllegalStateException("Native decompilation failed: " + result.getErrorMessage());
            }
        } finally {
            decompiler.dispose();
        }
        Files.writeString(Path.of(getScriptArgs()[0]), "PASS\n");
        println("XENON_EXTENSION_SMOKE_PASS helpers=16 residual_call_return=0 vmx=3 decompiler=PASS");
    }
}
