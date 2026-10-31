import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import xenon360.analysis.XenonEvidence;

/** Native execution, independent byte-array oracle, and architectural side effects. */
public class XenonVmxPermuteOptimizationTest extends GhidraScript {
    private static final long PC=0x82001240L,DATA=0x82002000L;
    private static final int[] EDGES={0,31,32,63,64,95,96,127};
    private int checks,executions,minOps=Integer.MAX_VALUE,maxOps;
    private final Map<String,BigInteger> guards=new LinkedHashMap<>();
    private final Map<String,Integer> coverage=new TreeMap<>();
    private final Set<Integer> destinations=new TreeSet<>(),sourcesA=new TreeSet<>(),sourcesB=new TreeSet<>(),controls=new TreeSet<>();
    private final boolean[][] selectors=new boolean[16][256];
    private final MessageDigest digest;
    private Map<String,Object> last=new LinkedHashMap<>();
    public XenonVmxPermuteOptimizationTest()throws Exception{digest=MessageDigest.getInstance("SHA-256");}
    private void check(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
    private void guard(String name,int index){
        Register r=currentProgram.getRegister(name);check(r!=null,"guard exists "+name);
        byte[] value=new byte[r.getMinimumByteSize()];for(int i=0;i<value.length;i++)value[i]=(byte)(0x91+index*13+i*7);
        guards.put(name,new BigInteger(1,value));
    }
    private void execute(String group,int d,int a,int b,int c,byte[] av,byte[] bv,byte[] cv)throws Exception{
        var effective=XenonVmxPermuteOracle.effective(a,b,c,av,bv,cv);
        av=effective[0];bv=effective[1];cv=effective[2];
        byte[] bytes=XenonVmxPermuteOracle.word(XenonVmxPermuteOracle.encoding(d,a,b,c));
        byte[] expected=XenonVmxPermuteOracle.permute(av,bv,cv);
        String context=String.format("d=%d a=%d b=%d c=%d",d,a,b,c);
        last=new LinkedHashMap<>();last.put("context",context);last.put("group",group);
        last.put("a",HexFormat.of().formatHex(av));last.put("b",HexFormat.of().formatHex(bv));last.put("c",HexFormat.of().formatHex(cv));last.put("expected",HexFormat.of().formatHex(expected));
        currentProgram.getMemory().setBytes(toAddr(PC),bytes);
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        check(ins!=null&&ins.getMnemonicString().equals("vperm128"),"decode "+context);
        check(ins.getLength()==4&&ins.getFlowType().isFallthrough(),"length and architectural flow "+context);
        check(ins.getNumOperands()==4,"four operands");
        int oi=0;for(int reg:new int[]{d,a,b,c})check(ins.getDefaultOperandRepresentation(oi++).equals("v"+reg),"operand decoding "+context);
        Register destination=currentProgram.getRegister(XenonVmxPermuteOracle.vr(d));int writes=0;
        minOps=Math.min(minOps,ins.getPcode().length);maxOps=Math.max(maxOps,ins.getPcode().length);
        for(PcodeOp op:ins.getPcode()){
            check(Set.of(PcodeOp.COPY,PcodeOp.SUBPIECE,PcodeOp.PIECE,PcodeOp.INT_ZEXT,PcodeOp.INT_SEXT,
                PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_OR,PcodeOp.INT_AND,PcodeOp.INT_XOR,
                PcodeOp.INT_ADD,PcodeOp.INT_SUB,PcodeOp.INT_MULT,PcodeOp.INT_NEGATE,PcodeOp.INT_2COMP).contains(op.getOpcode()),"pure native operation "+op);
            var output=op.getOutput();if(output!=null&&!output.isUnique()){
                check(output.isRegister()&&output.getAddress().equals(destination.getAddress())&&output.getSize()==16,"only full destination write "+context);writes++;
            }
        }
        check(writes==1,"one full destination write "+context);
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        try{
            for(var item:guards.entrySet())e.writeRegister(item.getKey(),item.getValue());
            e.writeRegister(XenonVmxPermuteOracle.vr(a),new BigInteger(1,av));e.writeRegister(XenonVmxPermuteOracle.vr(b),new BigInteger(1,bv));e.writeRegister(XenonVmxPermuteOracle.vr(c),new BigInteger(1,cv));
            e.writeRegister(e.getPCRegister(),PC);byte[] memory=HexFormat.of().parseHex("00112233445566778899aabbccddeeff");e.writeMemory(toAddr(DATA),memory);
            check(e.step(monitor),"execute "+context+": "+e.getLastError());executions++;
            BigInteger actual=e.readRegister(XenonVmxPermuteOracle.vr(d));last.put("actual",actual.toString(16));
            check(actual.equals(new BigInteger(1,expected)),"guest byte permutation oracle "+context);
            Map<String,BigInteger> after=new HashMap<>(guards);
            after.put(XenonVmxPermuteOracle.vr(a),new BigInteger(1,av));after.put(XenonVmxPermuteOracle.vr(b),new BigInteger(1,bv));after.put(XenonVmxPermuteOracle.vr(c),new BigInteger(1,cv));after.put(XenonVmxPermuteOracle.vr(d),new BigInteger(1,expected));
            for(var item:after.entrySet())check(e.readRegister(item.getKey()).equals(item.getValue()),"register preserved/updated "+item.getKey()+" "+context);
            for(int r=0;r<32;r++)for(int lane=0;lane<4;lane++)check(e.readRegister("vr"+r+"_32_"+lane).equals(after.get(XenonVmxPermuteOracle.vr(r)).shiftRight((3-lane)*32).and(new BigInteger("ffffffff",16))),"storage alias "+r+"/"+lane);
            check(Arrays.equals(memory,e.readMemory(toAddr(DATA),16)),"memory sentinel");check(Arrays.equals(bytes,e.readMemory(toAddr(PC),4)),"instruction bytes unchanged");
            check(e.readRegister(e.getPCRegister()).longValue()==PC+4,"PC advances four");
            digest.update(bytes);digest.update(av);digest.update(bv);digest.update(cv);digest.update(expected);
            byte[] actualBytes=actual.toByteArray();digest.update((byte)actualBytes.length);digest.update(actualBytes);
        }finally{e.dispose();}
        destinations.add(d);sourcesA.add(a);sourcesB.add(b);controls.add(c);
        coverage.merge("partition_"+XenonVmxPermuteOracle.partition(d,a,b,c),1,Integer::sum);coverage.merge(group,1,Integer::sum);
        for(int i=0;i<16;i++)selectors[i][cv[i]&255]=true;
    }
    @Override protected void run()throws Exception{
        Path output=Path.of(getScriptArgs()[0]);
        try{
            for(int r=0;r<128;r++)guard(XenonVmxPermuteOracle.vr(r),r);
            for(int r=0;r<32;r++){guard("r"+r,128+r);guard("vs"+r,160+r);}
            for(String n:new String[]{"crall","xer_so","xer_ov","xer_ov32","xer_ca","xer_ca32","xer_count","LR","CTR","MSR"})guard(n,guards.size());
            // Exhaust every encoded A/B pair, including equal low indices in different banks.
            for(int a=0;a<128;a++)for(int b=0;b<128;b++){
                currentProgram.getMemory().setBytes(toAddr(PC),XenonVmxPermuteOracle.word(XenonVmxPermuteOracle.encoding(127,a,b,0)));
                var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
                check(ins!=null&&ins.getMnemonicString().equals("vperm128"),"identity decode");
                boolean wide=Arrays.stream(ins.getPcode()).anyMatch(op->op.getOutput()!=null&&op.getOutput().getSize()==32);
                check(wide==(a!=b),"only exact seven-bit A/B equality selects the 128-bit path: "+a+"/"+b);
                check(ins.getNumOperands()==4&&ins.getDefaultOperandRepresentation(1).equals("v"+a)&&ins.getDefaultOperandRepresentation(2).equals("v"+b),"unchanged operand display");
            }
            for(int a=0;a<128;a++)for(int c=0;c<8;c++)for(int d:new int[]{a,c,(a+37)%128})for(int mask=0;mask<9;mask++)
                execute("same_source_all_banks",d,a,a,c,XenonVmxPermuteOracle.pattern(0,0),XenonVmxPermuteOracle.pattern(1,1),XenonVmxPermuteOracle.control(mask));
            // Equal runtime contents in different registers must still use the general path.
            for(int a=0;a<128;a++)for(int mask=0;mask<9;mask++)
                execute("equal_contents_distinct_registers",127,a,(a+32)%128,7,XenonVmxPermuteOracle.pattern(1,0),XenonVmxPermuteOracle.pattern(1,0),XenonVmxPermuteOracle.control(mask));
            check(executions==28800,"all focused execution cases");
            Map<String,Object> report=new LinkedHashMap<>();report.put("schema","xenon360/native-permute-optimization-v1");report.put("status","PASS");report.put("checks",checks);report.put("pcode_executions",executions);report.put("coverage",coverage);
            report.put("destinations",destinations);report.put("sources_a",sourcesA);report.put("sources_b",sourcesB);report.put("controls",controls);report.put("encoded_a_b_pairs",16384);report.put("output_positions",16);
            report.put("guard_registers_per_case",guards.size());report.put("low_bank_aliases_per_case",128);report.put("raw_ops_min",minOps);report.put("raw_ops_max",maxOps);
            report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));report.put("userop_emulation_callbacks",0);report.put("oracle","guest-order byte-array concatenation and indexing after actual alias initialization");report.put("all_operand_tuples_exhaustive",false);
            XenonEvidence.writeAtomic(output,report);println("XENON_VMX_PERMUTE_OPTIMIZATION_PASS checks="+checks+" executions="+executions);
        }catch(Throwable failure){XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"pcode_executions",executions,"error",failure.toString(),"last",last));throw failure;}
    }
}
