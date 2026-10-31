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

/** Executes generated p-code with no userop callbacks. The oracle copies bytes
 * in architectural order; it does not reproduce the SLEIGH shift expression. */
public class XenonVmxMergeTest extends GhidraScript {
    private static final long PC=0x82001240L, DATA=0x82002000L;
    private static final int[] EDGES={0,31,32,63,64,95,96,127};
    private int checks,executions;
    private final Map<String,BigInteger> guards=new LinkedHashMap<>();
    private final Map<String,Integer> coverage=new TreeMap<>();
    private final Set<Integer> destinations=new TreeSet<>(),sourcesA=new TreeSet<>(),sourcesB=new TreeSet<>();
    private final MessageDigest digest;
    public XenonVmxMergeTest() throws Exception {digest=MessageDigest.getInstance("SHA-256");}
    private void check(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
    private String vr(int r){return r<32?"vs"+(r+32):"v"+r;}
    private byte[] word(int n){return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(n).array();}
    private int encoding(boolean low,int d,int a,int b){
        return (low?0x18000340:0x18000300)|(d&31)<<21|(a&31)<<16|(b&31)<<11|
            (d>>>5)<<2|(a&32)|((a&64)<<4)|(b>>>5);
    }
    private byte[] oracle(boolean low,byte[] a,byte[] b){
        byte[] result=new byte[16];int first=low?8:0;
        System.arraycopy(a,first,result,0,4);System.arraycopy(b,first,result,4,4);
        System.arraycopy(a,first+4,result,8,4);System.arraycopy(b,first+4,result,12,4);
        return result;
    }
    private void guard(String name,int index){
        Register r=currentProgram.getRegister(name);check(r!=null,"guard exists "+name);
        byte[] value=new byte[r.getMinimumByteSize()];
        for(int i=0;i<value.length;i++)value[i]=(byte)(0x91+index*13+i*7);
        guards.put(name,new BigInteger(1,value));
    }
    private void execute(boolean low,int d,int a,int b,byte[] av,byte[] bv)throws Exception{
        // One architectural source register cannot simultaneously hold two values.
        if(a==b)bv=av;
        byte[] bytes=word(encoding(low,d,a,b)),expected=oracle(low,av,bv);
        String context=String.format("%s d=%d a=%d b=%d",low?"low":"high",d,a,b);
        currentProgram.getMemory().setBytes(toAddr(PC),bytes);
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        check(ins!=null&&ins.getMnemonicString().equals(low?"vmrglw128":"vmrghw128"),"decode "+context);
        check(ins.getLength()==4,"instruction length "+context);
        Register destination=currentProgram.getRegister(vr(d));int writes=0;
        for(PcodeOp op:ins.getPcode()){
            check(Set.of(PcodeOp.COPY,PcodeOp.SUBPIECE,PcodeOp.PIECE,PcodeOp.INT_ZEXT,
                PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_OR,PcodeOp.INT_AND,PcodeOp.INT_ADD).contains(op.getOpcode()),"pure native operation "+op+" "+context);
            var output=op.getOutput();
            if(output!=null&&!output.isUnique()){
                check(output.isRegister()&&output.getAddress().equals(destination.getAddress())&&output.getSize()==16,"only full destination write "+context);writes++;
            }
        }
        check(writes==1,"one full destination write "+context);
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            for(var item:guards.entrySet())e.writeRegister(item.getKey(),item.getValue());
            e.writeRegister(vr(a),new BigInteger(1,av));e.writeRegister(vr(b),new BigInteger(1,bv));
            e.writeRegister(e.getPCRegister(),PC);
            byte[] memory=HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
            e.writeMemory(toAddr(DATA),memory);
            check(e.step(monitor),"execute "+context+": "+e.getLastError());executions++;
            check(e.readRegister(vr(d)).equals(new BigInteger(1,expected)),"byte-copy oracle "+context);
            Map<String,BigInteger> after=new HashMap<>(guards);
            after.put(vr(a),new BigInteger(1,av));after.put(vr(b),new BigInteger(1,bv));after.put(vr(d),new BigInteger(1,expected));
            for(var item:after.entrySet())check(e.readRegister(item.getKey()).equals(item.getValue()),"register preserved/updated "+item.getKey()+" "+context);
            // Verify every low-bank word alias, including source and unrelated registers.
            for(int r=0;r<32;r++)for(int lane=0;lane<4;lane++)
                check(e.readRegister("vr"+r+"_32_"+lane).equals(after.get(vr(r)).shiftRight((3-lane)*32).and(new BigInteger("ffffffff",16))),"storage alias "+r+"/"+lane+" "+context);
            check(Arrays.equals(memory,e.readMemory(toAddr(DATA),16)),"memory sentinel "+context);
            check(Arrays.equals(bytes,e.readMemory(toAddr(PC),4)),"instruction memory unchanged "+context);
            check(e.readRegister(e.getPCRegister()).longValue()==PC+4,"PC advances four "+context);
            digest.update(bytes);digest.update(av);digest.update(bv);digest.update(expected);
            byte[] actual=e.readRegister(vr(d)).toByteArray();digest.update((byte)actual.length);digest.update(actual);
        }finally{e.dispose();}
        destinations.add(d);sourcesA.add(a);sourcesB.add(b);
        String alias=d==a&&a==b?"all_equal":a==b?"a_equals_b":d==a?"d_equals_a":d==b?"d_equals_b":"all_distinct";
        coverage.merge(alias,1,Integer::sum);coverage.merge(low?"low":"high",1,Integer::sum);
    }
    @Override protected void run()throws Exception{
        for(int r=0;r<128;r++)guard(vr(r),r);
        for(int r=0;r<32;r++){guard("r"+r,128+r);guard("vs"+r,160+r);}
        for(String n:new String[]{"crall","xer_so","xer_ov","xer_ov32","xer_ca","xer_ca32","xer_count","LR","CTR","MSR"})guard(n,guards.size());
        // Independent words: eight distinct values, alternating bits, zero/all ones,
        // sign boundaries, mixed halves, and byte-sensitive high/low patterns.
        String[][] hex={
            {"0123456789abcdeffedcba9876543210","d34a718dc253ee001122bbaa55ff0080"},
            {"aaaaaaaa55555555aa55aa5555aa55aa","cccccccc33333333cc33cc3333cc33cc"},
            {"00000000ffffffff00000000ffffffff","ffffffff00000000ffffffff00000000"},
            {"800000007fffffff80000001fffffffe","0000000100000000ffffffff7ffffffe"},
            {"000102031011121380818283f0f1f2f3","040506071415161784858687f4f5f6f7"}
        };
        for(boolean low:new boolean[]{false,true}){
            for(int d=0;d<128;d++){
                int other=(d+37)%128,third=(d+73)%128;
                for(int[] ab:new int[][]{{d,other},{other,d},{other,other},{d,d},{other,third},{(d+32)%128,(d+64)%128}})
                    for(String[] pair:hex)execute(low,d,ab[0],ab[1],HexFormat.of().parseHex(pair[0]),HexFormat.of().parseHex(pair[1]));
            }
            for(int d:EDGES)for(int a:EDGES)for(int b:EDGES)
                execute(low,d,a,b,HexFormat.of().parseHex(hex[0][0]),HexFormat.of().parseHex(hex[0][1]));
        }
        check(destinations.size()==128&&sourcesA.size()==128&&sourcesB.size()==128,"all registers in all operand roles");
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","xenon360/native-merges-v1");report.put("status","PASS");
        report.put("checks",checks);report.put("pcode_executions",executions);report.put("coverage",coverage);
        report.put("destinations",destinations);report.put("sources_a",sourcesA);report.put("sources_b",sourcesB);
        report.put("guard_registers_per_case",guards.size());report.put("low_bank_aliases_per_case",128);
        report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));report.put("userop_emulation_callbacks",0);
        report.put("oracle","guest-order byte arrays and four explicit word copies");report.put("hardware_equivalence_claimed",false);
        XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),report);
        println("XENON_VMX_MERGE_PASS checks="+checks+" executions="+executions);
    }
}
