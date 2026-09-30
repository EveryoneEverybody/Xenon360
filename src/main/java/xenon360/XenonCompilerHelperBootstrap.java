package xenon360;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.database.SpecExtension;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Models standard Xenon compiler save helpers before normal Auto Analysis. */
final class XenonCompilerHelperBootstrap {
    private static final int FULL_SAVE_REGISTERS = 18;
    private static final int CALLABLE_SAVE_ENTRIES = 16;
    private static final int SAVE_BYTES = (FULL_SAVE_REGISTERS + 2) * 4;

    private static final String FIXUP_NAME = "xenon_ppc_savegpr_noop";
    private static final String FIXUP_XML =
        "<callfixup name=\"" + FIXUP_NAME + "\">\n" +
        "  <pcode><body><![CDATA[\n" +
        "    r3=r3; r4=r4; r5=r5; r6=r6; r7=r7;\n" +
        "    r8=r8; r9=r9; r10=r10; r11=r11; r12=r12;\n" +
        "  ]]></body></pcode>\n" +
        "</callfixup>";

    record Result(int families, int entries, int createdFunctions) {}
    private XenonCompilerHelperBootstrap() {}

    static Result apply(Program program, TaskMonitor monitor)
            throws Exception {
        List<Address> starts = findSaveFamilies(program, monitor);
        if (starts.isEmpty()) return new Result(0, 0, 0);

        try {
            SpecExtension extension = new SpecExtension(program);
            extension.testExtensionDocument(FIXUP_XML);
            extension.addReplaceCompilerSpecExtension(FIXUP_XML, monitor);
        }
        catch (Exception ex) {
            throw new IllegalStateException("Unable to install Xenon compiler-helper callfixup", ex);
        }

        FunctionManager fm = program.getFunctionManager();
        int modeled = 0;
        int created = 0;

        for (Address start : starts) {
            monitor.checkCancelled();
            Address end = start.add(SAVE_BYTES - 1L);
            DisassembleCommand disassemble =
                new DisassembleCommand(start, new AddressSet(start, end), true);
            disassemble.enableCodeAnalysis(false);
            if (!disassemble.applyTo(program, monitor)) {
                throw new IllegalStateException(
                    "Unable to disassemble Xenon save-helper family at " + start);
            }

            for (int i = 0; i < CALLABLE_SAVE_ENTRIES; i++) {
                Address entry = start.add(i * 4L);
                Function f = fm.getFunctionAt(entry);
                if (f == null) {
                    Function owner = fm.getFunctionContaining(entry);
                    if (owner != null && inSaveFamily(owner.getEntryPoint(), start)) {
                        owner.setBody(singleInstruction(owner.getEntryPoint()));
                    }
                    try {
                        f = fm.createFunction(
                            null, entry, singleInstruction(entry), SourceType.ANALYSIS);
                        created++;
                    }
                    catch (Exception ex) {
                        throw new IllegalStateException(
                            "Unable to create Xenon save-helper entry at " + entry, ex);
                    }
                }
                else if (f.getBody().getNumAddresses() != 4) {
                    f.setBody(singleInstruction(entry));
                }
                f.setNoReturn(false);
                f.setCallFixup(FIXUP_NAME);
                modeled++;
            }
        }
        return new Result(starts.size(), modeled, created);
    }
    private static AddressSet singleInstruction(Address entry) {
        return new AddressSet(entry, entry.add(3));
    }

    private static boolean inSaveFamily(Address entry, Address start) {
        return entry.compareTo(start) >= 0 &&
            entry.compareTo(start.add(SAVE_BYTES - 1L)) <= 0;
    }

    private static List<Address> findSaveFamilies(Program program, TaskMonitor monitor)
            throws CancelledException {
        List<Address> result = new ArrayList<>();
        Memory memory = program.getMemory();
        for (MemoryBlock block : memory.getBlocks()) {
            if (!block.isExecute() || !block.isInitialized()) continue;
            Address cursor = align4(block.getStart());
            Address last;
            try {
                last = block.getEnd().subtract(SAVE_BYTES - 1L);
            }
            catch (Exception ex) {
                continue;
            }
            while (cursor.compareTo(last) <= 0) {
                monitor.checkCancelled();
                if (matchesSaveFamily(memory, cursor)) result.add(cursor);
                try {
                    cursor = cursor.addNoWrap(4);
                }
                catch (Exception ex) {
                    break;
                }
            }
        }
        return result;
    }

    private static Address align4(Address address) {
        long offset = address.getOffset();
        long aligned = (offset + 3L) & ~3L;
        return address.getAddressSpace().getAddress(aligned);
    }
    private static boolean matchesSaveFamily(Memory memory, Address start) {
        try {
            for (int i = 0; i < FULL_SAVE_REGISTERS; i++) {
                int reg = 14 + i;
                int displacement = -0x98 + i * 8;
                if (memory.getInt(start.add(i * 4L), true) !=
                        encodeDs(62, reg, 1, displacement)) {
                    return false;
                }
            }
            Address stw = start.add(FULL_SAVE_REGISTERS * 4L);
            Address blr = stw.add(4);
            return memory.getInt(stw, true) == encodeD(36, 12, 1, -8)
                && memory.getInt(blr, true) == 0x4e800020;
        }
        catch (MemoryAccessException | RuntimeException ex) {
            return false;
        }
    }

    private static int encodeDs(int opcode, int reg, int base, int displacement) {
        return (opcode << 26) | (reg << 21) | (base << 16) |
            (displacement & 0xfffc);
    }

    private static int encodeD(int opcode, int reg, int base, int displacement) {
        return (opcode << 26) | (reg << 21) | (base << 16) |
            (displacement & 0xffff);
    }
}
