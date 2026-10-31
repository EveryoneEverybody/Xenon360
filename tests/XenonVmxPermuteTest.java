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
public class XenonVmxPermuteTest extends GhidraScript {
    private static final long PC=0x82001240L,DATA=0x82002000L;
    private static final int[] EDGES={0,31,32,63,64,95,96,127};
    private int checks,executions,minOps=Integer.MAX_VALUE,maxOps;
    private final Map<String,BigInteger> guards=new LinkedHashMap<>();
    private final Map<String,Integer> coverage=new TreeMap<>();
    private final Set<Integer> destinations=new TreeSet<>(),sourcesA=new TreeSet<>(),sourcesB=new TreeSet<>(),controls=new TreeSet<>();
    private final boolean[][] selectors=new boolean[16][256];
    private final MessageDigest digest;
    private Map<String,Object> last=new LinkedHashMap<>();
    public XenonVmxPermuteTest()throws Exception{digest=MessageDigest.getInstance("SHA-256");}
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
            for(int pattern=0;pattern<3;pattern++)for(int position=0;position<16;position++)for(int value=0;value<256;value++){
                byte[] c=XenonVmxPermuteOracle.control(8);c[position]=(byte)value;
                execute("selector_sweep",127,32,64,value%8,XenonVmxPermuteOracle.pattern(pattern,0),XenonVmxPermuteOracle.pattern(pattern,1),c);
            }
            for(int d=0;d<128;d++)for(int p=0;p<6;p++)for(int mask=0;mask<9;mask++)
                execute("register_patterns",d,(d+37)%128,(d+73)%128,d%8,XenonVmxPermuteOracle.pattern(p,0),XenonVmxPermuteOracle.pattern(p,1),XenonVmxPermuteOracle.control(mask));
            for(int c=0;c<8;c++)for(int[] partition:XenonVmxPermuteOracle.partitions())for(int p=0;p<6;p++){
                int[] r=XenonVmxPermuteOracle.realize(partition,c);
                execute("equality_partitions",r[0],r[1],r[2],r[3],XenonVmxPermuteOracle.pattern(p,0),XenonVmxPermuteOracle.pattern(p,1),XenonVmxPermuteOracle.control(8));
            }
            for(int d:EDGES)for(int a:EDGES)for(int b:EDGES)for(int c=0;c<8;c++)execute("bank_boundaries",d,a,b,c,XenonVmxPermuteOracle.pattern(0,0),XenonVmxPermuteOracle.pattern(0,1),XenonVmxPermuteOracle.control(6));
            for(int low=0;low<32;low++)for(int bank=0;bank<4;bank++)execute("same_low_index",bank*32+low,((bank+1)%4)*32+low,((bank+2)%4)*32+low,low%8,XenonVmxPermuteOracle.pattern(1,0),XenonVmxPermuteOracle.pattern(1,1),XenonVmxPermuteOracle.control(7));
            Random random=new Random(0x536e61746976654cL);
            for(int i=0;i<512;i++){byte[] a=new byte[16],b=new byte[16],c=new byte[16];random.nextBytes(a);random.nextBytes(b);random.nextBytes(c);execute("random",random.nextInt(128),random.nextInt(128),random.nextInt(128),random.nextInt(8),a,b,c);}
            check(destinations.size()==128&&sourcesA.size()==128&&sourcesB.size()==128&&controls.size()==8,"all legal registers in each role");
            for(int i=0;i<16;i++)for(int v=0;v<256;v++)check(selectors[i][v],"all selectors at each byte");
            check(coverage.keySet().stream().filter(k->k.startsWith("partition_")).count()==15,"all 15 realizable equality partitions");
            Map<String,Object> report=new LinkedHashMap<>();report.put("schema","xenon360/native-permute-v1");report.put("status","PASS");report.put("checks",checks);report.put("pcode_executions",executions);report.put("coverage",coverage);
            report.put("destinations",destinations);report.put("sources_a",sourcesA);report.put("sources_b",sourcesB);report.put("controls",controls);report.put("selector_values_per_position",256);report.put("output_positions",16);
            report.put("guard_registers_per_case",guards.size());report.put("low_bank_aliases_per_case",128);report.put("raw_ops_min",minOps);report.put("raw_ops_max",maxOps);
            report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));report.put("userop_emulation_callbacks",0);report.put("oracle","guest-order byte-array concatenation and indexing after actual alias initialization");report.put("all_operand_tuples_exhaustive",false);
            XenonEvidence.writeAtomic(output,report);println("XENON_VMX_PERMUTE_PASS checks="+checks+" executions="+executions);
        }catch(Throwable failure){XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"pcode_executions",executions,"error",failure.toString(),"last",last));throw failure;}
    }
}
