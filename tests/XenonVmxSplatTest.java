import java.math.BigInteger;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import xenon360.analysis.XenonEvidence;

/** Byte-array oracle from the architectural lane rules; executes the emitted p-code
 * in Ghidra's emulator without userop callbacks. No SLEIGH-derived expected values.
 * Encoding fields follow pinned Xenia VX128_3. See docs/vmx128-native-splats.md.
 */
public class XenonVmxSplatTest extends GhidraScript {
    private static final long PC = 0x82001240L, DATA = 0x82002000L;
    private static final int[] EDGES = {0,31,32,63,64,95,96,127};
    private int checks, executions, wordCases, immediateCases, aliasCases;
    private final Map<String,BigInteger> guards = new LinkedHashMap<>();
    private final MessageDigest digest;
    public XenonVmxSplatTest() throws Exception { digest = MessageDigest.getInstance("SHA-256"); }
    private void check(boolean ok, String message) { checks++; if (!ok) throw new AssertionError(message); }
    private String vr(int r) { return r < 32 ? "vs" + (r + 32) : "v" + r; }
    private byte[] word(int n) { return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(n).array(); }
    private int encoding(boolean imm, int d, int s, int field) {
        return (imm ? 0x18000770 : 0x18000730) | (d & 31) << 21 |
            field << 16 | (s & 31) << 11 | (d >>> 5) << 2 | (s >>> 5);
    }
    private byte[] oracle(boolean imm, byte[] source, int field) {
        byte[] result = new byte[16];
        // Architectural byte order, with no 128-bit shifts mirroring the implementation.
        byte[] value = imm ? word(field < 16 ? field : field - 32) :
            Arrays.copyOfRange(source, (field % 4) * 4, (field % 4) * 4 + 4);
        for (int lane = 0; lane < 4; lane++) System.arraycopy(value, 0, result, lane * 4, 4);
        return result;
    }
    private void addGuard(String name, int index) {
        Register r = currentProgram.getRegister(name);
        check(r != null, "guard register exists: " + name);
        byte[] b = new byte[r.getMinimumByteSize()];
        for (int i = 0; i < b.length; i++) b[i] = (byte)(0x91 + index * 13 + i * 7);
        guards.put(name, new BigInteger(1,b));
    }
    private void execute(boolean imm, int d, int s, int field, byte[] source) throws Exception {
        int opcode = encoding(imm,d,s,field);
        byte[] bytes = word(opcode), expected = oracle(imm,source,field);
        currentProgram.getMemory().setBytes(toAddr(PC),bytes);
        var instruction = new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        String context = String.format("word=%08x d=%d s=%d field=%d",opcode,d,s,field);
        check(instruction.getMnemonicString().equals(imm ? "vspltisw128" : "vspltw128"),"decode " + context);
        check(instruction.getLength() == 4,"instruction width " + context);
        int writes = 0;
        Register dest = currentProgram.getRegister(vr(d));
        for (PcodeOp op : instruction.getPcode()) {
            check(op.getOpcode() != PcodeOp.CALLOTHER && op.getOpcode() != PcodeOp.LOAD &&
                  op.getOpcode() != PcodeOp.STORE && op.getOpcode() != PcodeOp.BRANCH &&
                  op.getOpcode() != PcodeOp.CBRANCH && op.getOpcode() != PcodeOp.BRANCHIND &&
                  op.getOpcode() != PcodeOp.CALL && op.getOpcode() != PcodeOp.RETURN,
                  "pure native dataflow " + context);
            var output = op.getOutput();
            if (output != null && !output.isUnique()) {
                check(output.isRegister() && output.getAddress().equals(dest.getAddress()) &&
                      output.getSize() == 16,"only complete destination write " + context);
                writes++;
            }
        }
        check(writes == 1,"single 128-bit destination write " + context);
        var e = new EmulatorHelper(currentProgram);
        try {
            for (var guard : guards.entrySet()) e.writeRegister(guard.getKey(),guard.getValue());
            if (!imm) e.writeRegister(vr(s),new BigInteger(1,source));
            e.writeRegister(e.getPCRegister(),PC);
            byte[] memory = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
            e.writeMemory(toAddr(DATA),memory);
            check(e.step(monitor),"execute " + context + ": " + e.getLastError());
            executions++;
            check(e.readRegister(vr(d)).equals(new BigInteger(1,expected)),"independent byte oracle " + context);
            for (var guard : guards.entrySet()) {
                if (guard.getKey().equals(vr(d))) continue;
                BigInteger value = !imm && guard.getKey().equals(vr(s)) ? new BigInteger(1,source) : guard.getValue();
                check(e.readRegister(guard.getKey()).equals(value),"preserved " + guard.getKey() + " " + context);
            }
            if (d < 32) for (int lane = 0; lane < 4; lane++) {
                check(e.readRegister("vr" + d + "_32_" + lane).equals(new BigInteger(1,Arrays.copyOfRange(expected,lane*4,lane*4+4))),
                      "standard AltiVec subregister alias " + context);
            }
            check(Arrays.equals(memory,e.readMemory(toAddr(DATA),16)),"memory unchanged " + context);
            check(e.readRegister(e.getPCRegister()).longValue() == PC + 4,"PC advances exactly one instruction " + context);
            digest.update(bytes); digest.update(expected);
            byte[] actual = e.readRegister(vr(d)).toByteArray();
            digest.update((byte)actual.length); digest.update(actual);
            if (imm) immediateCases++; else { wordCases++; if (d == s) aliasCases++; }
        } finally { e.dispose(); }
    }
    @Override protected void run() throws Exception {
        for (int r = 0; r < 128; r++) addGuard(vr(r),r);
        for (int r = 0; r < 32; r++) { addGuard("r"+r,128+r); addGuard("vs"+r,160+r); }
        for (String name : new String[]{"crall","xer_so","xer_ov","xer_ov32","xer_ca","xer_ca32","xer_count","LR","CTR","MSR"})
            addGuard(name,guards.size());
        // Independent constants include distinct high-bit words and endian-sensitive bytes.
        byte[][] patterns = {
            HexFormat.of().parseHex("0123456789abcdeffedcba9876543210"),
            HexFormat.of().parseHex("80000000ffffffff000000007fffffff"),
            HexFormat.of().parseHex("d34a718dc253ee001122bbaa55ff0080")
        };
        // Every source and destination register, each selector, and in-place aliases.
        for (int d = 0; d < 128; d++) for (int s : new int[]{d,(d+37)%128})
            for (int selector = 0; selector < 4; selector++) for (byte[] b : patterns)
                execute(false,d,s,selector,b);
        // Every cross-bank boundary pair, including adjacent 31/32, 63/64 and 95/96.
        for (int d : EDGES) for (int s : EDGES) for (int selector = 0; selector < 4; selector++)
            for (byte[] b : patterns) execute(false,d,s,selector,b);
        // Exhaust all signed 5-bit values (-16..15), rather than only representative signs.
        for (int d = 0; d < 128; d++) for (int bits = 0; bits < 32; bits++)
            execute(true,d,0,bits,patterns[0]);
        // Preserve existing decoder acceptance of unused source bits; no hardware validity claim.
        for (int d : EDGES) for (int bits = 0; bits < 32; bits++) execute(true,d,127,bits,patterns[0]);
        // Xenia/QEMU selector masking compatibility beyond canonical selectors 0..3.
        for (int d : EDGES) for (int s : new int[]{d,(d+37)%128}) for (int bits = 4; bits < 32; bits++)
            execute(false,d,s,bits,patterns[0]);
        var report = new LinkedHashMap<String,Object>();
        report.put("schema","xenon360/native-splats-v1"); report.put("status","PASS");
        report.put("checks",checks); report.put("pcode_executions",executions);
        report.put("word_cases",wordCases); report.put("immediate_cases",immediateCases);
        report.put("source_equals_destination_cases",aliasCases); report.put("guard_registers_per_case",guards.size());
        report.put("oracle","architectural big-endian byte-array copy; signed integer immediate serialized with ByteBuffer");
        report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));
        report.put("userop_emulation_callbacks",0); report.put("hardware_equivalence_claimed",false);
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),report);
        println("XENON_VMX_SPLAT_PASS checks="+checks+" executions="+executions);
    }
}
