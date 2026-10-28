import java.math.BigInteger;
import java.nio.*;
import java.nio.file.*;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.pcode.PcodeOp;
import xenon360.analysis.XenonEvidence;

/** Runs emitted p-code; no CALLOTHER callbacks are supplied to fake instruction semantics. */
public class XenonVmxSemanticTest extends GhidraScript {
    private int checks, executions;
    private static final long PC=0x82001240L, DATA=0x82002000L;
    private void check(boolean ok,String what) {checks++;if(!ok)throw new AssertionError(what);}
    private byte[] word(int opcode) {return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(opcode).array();}
    private String vr(int r) {return r<32?"vs"+(r+32):"v"+r;}
    private EmulatorHelper emulator(int opcode) {
        var e=new EmulatorHelper(currentProgram);
        e.writeMemory(toAddr(PC),word(opcode)); e.writeRegister(e.getPCRegister(),PC);
        return e;
    }
    private void step(EmulatorHelper e) throws Exception {check(e.step(monitor),"p-code execution: "+e.getLastError());executions++;}
    private int mem(int xo,int v,int ra,int rb) {return 4<<26 | (v&31)<<21 | ra<<16 | rb<<11 | xo<<6 | (v>>>5)<<2 | 3;}
    @Override protected void run() throws Exception {
        byte[] bytes=new byte[16], vector=new byte[16];
        for(int i=0;i<16;i++) {bytes[i]=(byte)(0x40+i);vector[i]=(byte)(0xa0+i);}
        int[] registers={0,31,32,63,64,95,96,127};
        for(int v:registers) for(int offset=0;offset<16;offset++) for(int op:new int[]{3,7,16,17,20,21}) {
            var e=emulator(mem(op,v,0,5));
            try {
                e.writeRegister("r0",0x12345678); // RA=0 must contribute zero, not r0.
                e.writeRegister("r5",DATA+offset); e.writeMemory(toAddr(DATA),bytes);
                e.writeRegister(vr(v),new BigInteger(1,vector));
                step(e);
                byte[] expected=bytes.clone();
                if(op==3) check(e.readRegister(vr(v)).equals(new BigInteger(1,bytes)),"aligned lvx128");
                if(op==16) {
                    expected=new byte[16];System.arraycopy(bytes,offset,expected,0,16-offset);
                    check(e.readRegister(vr(v)).equals(new BigInteger(1,expected)),"lvlx128 byte lanes v"+v+" offset="+offset);
                }
                if(op==17) {
                    expected=new byte[16];System.arraycopy(bytes,0,expected,16-offset,offset);
                    check(e.readRegister(vr(v)).equals(new BigInteger(1,expected)),"lvrx128 byte lanes v"+v+" offset="+offset);
                }
                if(op==7) expected=vector;
                if(op==20) System.arraycopy(vector,0,expected,offset,16-offset);
                if(op==21) System.arraycopy(vector,16-offset,expected,0,offset);
                if(op==7||op==20||op==21) check(Arrays.equals(e.readMemory(toAddr(DATA),16),expected),"partial store lanes/preservation");
                check(e.readRegister("r5").longValue()==DATA+offset,"address register preserved");
            } finally {e.dispose();}
        }
        // All 128 destinations, nonzero RA, and the original misdecoded retail word.
        for(int v=0;v<128;v++) {
            var e=emulator(mem(17,v,4,5));
            try {
                e.writeRegister("r4",DATA);e.writeRegister("r5",7);e.writeMemory(toAddr(DATA),bytes);step(e);
                byte[] expected=new byte[16];System.arraycopy(bytes,0,expected,9,7);
                check(e.readRegister(vr(v)).equals(new BigInteger(1,expected)),"lvrx128 complete register namespace "+v);
                check(e.readRegister("r4").longValue()==DATA&&e.readRegister("r5").longValue()==7,"load-right GPRs preserved");
            } finally {e.dispose();}
        }
        var retail=emulator(0x13c45c47); // lvrx128 v62,r4,r11; formerly vcmpneh. v30,v4,v11
        try {
            retail.writeRegister("r4",DATA);retail.writeRegister("r11",5);retail.writeMemory(toAddr(DATA),bytes);
            retail.writeRegister(vr(30),new BigInteger(1,vector));step(retail);
            byte[] expected=new byte[16];System.arraycopy(bytes,0,expected,11,5);
            check(retail.readRegister(vr(62)).equals(new BigInteger(1,expected)),"Source retail instruction writes v62");
            check(retail.readRegister(vr(30)).equals(new BigInteger(1,vector)),"Source retail instruction preserves false-alias v30");
        } finally {retail.dispose();}
        // An aligned right load must zero its destination without touching an unmapped page.
        var aligned=emulator(mem(17,127,0,5));
        try {
            aligned.writeRegister("r5",0x70000000);aligned.writeRegister(vr(127),new BigInteger(1,vector));step(aligned);
            check(aligned.readRegister(vr(127)).equals(BigInteger.ZERO),"aligned load-right is zero without memory access");
        } finally {aligned.dispose();}
        // Exercise aliases with independent constant vectors, including destination=input.
        for(int v:new int[]{0,31}) for(int offset=0;offset<16;offset++) for(int op:new int[]{519,551,647,679}) {
            var e=emulator(31<<26 | v<<21 | 4<<16 | 5<<11 | op<<1);
            try {
                e.writeRegister("r4",DATA);e.writeRegister("r5",offset);e.writeMemory(toAddr(DATA),bytes);
                e.writeRegister(vr(v),new BigInteger(1,vector));step(e);
                byte[] expected=bytes.clone();
                if(op==519) {expected=new byte[16];System.arraycopy(bytes,offset,expected,0,16-offset);}
                if(op==551) {expected=new byte[16];System.arraycopy(bytes,0,expected,16-offset,offset);}
                if(op==647)System.arraycopy(vector,0,expected,offset,16-offset);
                if(op==679)System.arraycopy(vector,16-offset,expected,0,offset);
                if(op==519||op==551)check(e.readRegister(vr(v)).equals(new BigInteger(1,expected)),"standard partial load");
                else check(Arrays.equals(e.readMemory(toAddr(DATA),16),expected),"standard partial store");
            } finally {e.dispose();}
        }
        // Exercise aliases with independent constant vectors, including destination=input.
        BigInteger a=new BigInteger("0123456789abcdeffedcba9876543210",16),b=new BigInteger("ff00ff00aa55aa551122334455667788",16);
        for(int[] regs:new int[][]{{104,13,12},{1,1,2},{127,96,127},{32,31,64}}) {
            // Use the assembler-independent known VX128 field mapping from the decoder specification.
            int d=regs[0],ra=regs[1],rb=regs[2];
            int encoding=5<<26 | (d&31)<<21 | (ra&31)<<16 | (rb&31)<<11 |
                9<<6 | 16 | (d>>>5)<<2 | (ra>>>5&1)<<5 | (ra>>>6&1)<<10 | (rb>>>5);
            var e=emulator(encoding);
            try {e.writeRegister(vr(ra),a);e.writeRegister(vr(rb),b);step(e);
                check(e.readRegister(vr(d)).equals(a.andNot(b)),"vandc128 executable semantics and aliases");}
            finally {e.dispose();}
        }
        // Independent word-array oracles cover every selector, rotation and insertion mask.
        byte[] sourceWords=HexFormat.of().parseHex("0123456789abcdeffedcba9876543210");
        byte[] destinationWords=HexFormat.of().parseHex("ff00ff00aa55aa551122334455667788");
        for(int[] regs:new int[][]{{0,31},{32,63},{64,95},{96,127},{62,62},{127,127}}) {
            int d=regs[0],s=regs[1];
            for(int selector=0;selector<256;selector++) {
                int encoding=6<<26 | (d&31)<<21 | (selector&31)<<16 | (s&31)<<11 |
                    0x210 | (selector>>>5)<<6 | (d>>>5)<<2 | (s>>>5);
                var e=emulator(encoding);
                try {
                    e.writeRegister(vr(s),new BigInteger(1,sourceWords));step(e);byte[] expected=new byte[16];
                    for(int lane=0;lane<4;lane++)System.arraycopy(sourceWords,((selector>>>(6-lane*2))&3)*4,expected,lane*4,4);
                    check(e.readRegister(vr(d)).equals(new BigInteger(1,expected)),"vpermwi128 selector="+selector+" d="+d+" s="+s);
                } finally {e.dispose();}
            }
            for(int mask=0;mask<32;mask++)for(int rotation=0;rotation<4;rotation++) {
                int encoding=6<<26 | (d&31)<<21 | mask<<16 | (s&31)<<11 | 0x710 | rotation<<6 | (d>>>5)<<2 | (s>>>5);
                var e=emulator(encoding);
                try {
                    e.writeRegister(vr(d),new BigInteger(1,destinationWords));e.writeRegister(vr(s),new BigInteger(1,sourceWords));
                    byte[] expected=(d==s?sourceWords:destinationWords).clone();
                    for(int lane=0;lane<4;lane++)if((mask&(8>>>lane))!=0)System.arraycopy(sourceWords,((lane+rotation)&3)*4,expected,lane*4,4);
                    step(e);check(e.readRegister(vr(d)).equals(new BigInteger(1,expected)),"vrlimi128 mask="+mask+" rotation="+rotation+" aliases="+(d==s));
                } finally {e.dispose();}
            }
        }
        // An aligned right store must not read or write an unmapped page.
        var e=emulator(mem(21,127,0,5));
        try {e.writeRegister("r5",0x70000000);step(e);} finally {e.dispose();}
        var decoder=new PseudoDisassembler(currentProgram);
        String[] names={"vnmsubfp128","vandc128","vcmpbfp128","vnor128","lvlx128","vrfip128"};
        for(int i=0;i<names.length;i++) check(decoder.disassemble(toAddr(0x82001200L+i*4)).getMnemonicString().equals(names[i]),"v07 golden mnemonic "+names[i]);
        var report=Map.of("schema","xenon360/vmx-regression-v2","status","PASS","checks",checks,"pcode_executions",executions,
            "memory_offsets",16,"register_banks",4,"userop_emulation_callbacks",0,
            "limits",List.of("Fused floating point, estimates, saturation and compare-record userops remain opaque; no hardware equivalence is claimed."));
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),report);
        println("XENON_VMX_SEMANTIC_PASS checks="+checks+" executions="+executions);
    }
}
