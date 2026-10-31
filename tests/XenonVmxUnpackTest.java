import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.lang.Register;
import ghidra.program.model.pcode.PcodeOp;
import xenon360.analysis.XenonEvidence;

/** Native execution, exhaustive register pairs, aliases, subtype controls and
 * optional frozen corpus words. Never emulates an opaque userop callback. */
public class XenonVmxUnpackTest extends GhidraScript {
    private static final long PC=0x82001240L,DATA=0x82002000L;
    private final Map<String,BigInteger> guards=new LinkedHashMap<>();
    private final Map<String,Integer> coverage=new TreeMap<>();
    private final MessageDigest digest;
    private int checks,executions,rawMin=Integer.MAX_VALUE,rawMax,controls;
    public XenonVmxUnpackTest()throws Exception{digest=MessageDigest.getInstance("SHA-256");}
    private void check(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
    private String vr(int r){return XenonVmxUnpackOracle.register(r);}
    private void guard(String name,int index){
        Register r=currentProgram.getRegister(name);check(r!=null,"guard exists "+name);
        byte[] value=new byte[r.getMinimumByteSize()];for(int i=0;i<value.length;i++)value[i]=(byte)(0x91+index*13+i*7);
        guards.put(name,new BigInteger(1,value));
    }
    private void execute(int word,boolean low,int d,int b,byte[] source,String group)throws Exception {
        String context=String.format("%08x d=%d b=%d %s",word,d,b,group);
        byte[] bytes=XenonVmxUnpackOracle.instruction(word),expected=XenonVmxUnpackOracle.reference(low,source);
        currentProgram.getMemory().setBytes(toAddr(PC),bytes);
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        check(ins!=null&&ins.getMnemonicString().equals(low?"vupklsh128":"vupkhsh128"),"subtype decode "+context);
        check(ins.toString().equals((low?"vupklsh128":"vupkhsh128")+" v"+d+",v"+b),"operand mapping "+context);
        Register dest=currentProgram.getRegister(vr(d));int writes=0;
        for(PcodeOp op:ins.getPcode()) {
            check(Set.of(PcodeOp.COPY,PcodeOp.SUBPIECE,PcodeOp.PIECE,PcodeOp.INT_SEXT,PcodeOp.INT_ZEXT,
                PcodeOp.INT_ADD,PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_OR,PcodeOp.INT_AND).contains(op.getOpcode()),"native pure operation "+context+" "+op);
            var o=op.getOutput();if(o!=null&&!o.isUnique()){
                check(o.isRegister()&&o.getAddress().equals(dest.getAddress())&&o.getSize()==16,"destination-only full write "+context);writes++;
            }
        }
        check(writes==1,"one full destination write "+context);
        rawMin=Math.min(rawMin,ins.getPcode().length);rawMax=Math.max(rawMax,ins.getPcode().length);
        EmulatorHelper e=new EmulatorHelper(currentProgram);
        try {
            for(var x:guards.entrySet())e.writeRegister(x.getKey(),x.getValue());
            e.writeRegister(vr(b),new BigInteger(1,source));e.writeRegister(e.getPCRegister(),PC);
            byte[] sentinel=HexFormat.of().parseHex("51a270d399b84fc62de01f8639cae075");e.writeMemory(toAddr(DATA),sentinel);
            check(e.step(monitor),"native execution "+context+" "+e.getLastError());executions++;
            BigInteger actual=e.readRegister(vr(d));check(actual.equals(new BigInteger(1,expected)),"signed-halfword byte oracle "+context+" source="+HexFormat.of().formatHex(source)+" actual="+actual.toString(16)+" expected="+HexFormat.of().formatHex(expected));
            Map<String,BigInteger> after=new HashMap<>(guards);after.put(vr(b),new BigInteger(1,source));after.put(vr(d),new BigInteger(1,expected));
            for(var x:after.entrySet())check(e.readRegister(x.getKey()).equals(x.getValue()),"state guard "+x.getKey()+" "+context);
            for(int r=0;r<32;r++)for(int lane=0;lane<4;lane++)check(e.readRegister("vr"+r+"_32_"+lane).equals(after.get(vr(r)).shiftRight((3-lane)*32).and(new BigInteger("ffffffff",16))),"low-bank alias "+context);
            check(Arrays.equals(sentinel,e.readMemory(toAddr(DATA),16)),"RAM guard "+context);
            check(Arrays.equals(bytes,e.readMemory(toAddr(PC),4)),"code unchanged "+context);
            check(e.readRegister(e.getPCRegister()).longValue()==PC+4,"PC advances "+context);
            digest.update(bytes);digest.update(source);digest.update(expected);byte[] actualBytes=actual.toByteArray();digest.update((byte)actualBytes.length);digest.update(actualBytes);
        } finally {e.dispose();}
        coverage.merge(group,1,Integer::sum);coverage.merge(low?"low":"high",1,Integer::sum);coverage.merge(d==b?"alias":"distinct",1,Integer::sum);
    }
    private void controls()throws Exception {
        var decoder=new PseudoDisassembler(currentProgram);
        for(boolean low:new boolean[]{false,true})for(int a=0;a<128;a++)for(int edge:new int[]{0,127}) {
            int w=(low?0x180003c0:0x18000380)|((edge&31)<<21)|((edge&31)<<11)|((edge>>>5)<<2)|(edge>>>5)|((a&31)<<16)|(a&32)|((a&64)<<4);
            var ins=decoder.disassemble(toAddr(PC),XenonVmxUnpackOracle.instruction(w));
            check(ins!=null,"inherited unpack decoding");
            check(ins.getMnemonicString().equals(low?(a==96?"vupklsh128":"vupklsb128"):(a==96?"vupkhsh128":"vupkhsb128")),"exact selector and reserved controls a="+a);
            long opaque=Arrays.stream(ins.getPcode()).filter(x->x.getOpcode()==PcodeOp.CALLOTHER).count();
            check(opaque==(a==96?0:1),"uncertain selectors retain opaque behavior a="+a);controls++;
        }
        for(boolean low:new boolean[]{false,true})for(int bit:new int[]{4,26,27,28,29,30,31}) {
            int w=XenonVmxUnpackOracle.encoding(low,37,65)^(1<<bit);
            try {var ins=decoder.disassemble(toAddr(PC),XenonVmxUnpackOracle.instruction(w));check(ins==null||!Set.of("vupkhsh128","vupklsh128").contains(ins.getMnemonicString()),"fixed-opcode bit control "+bit);}
            catch(ghidra.program.model.lang.UnknownInstructionException ex){checks++;}controls++;
        }
    }
    private void test()throws Exception {
        Path output=Path.of(getScriptArgs()[0]);String mode=getScriptArgs().length>1?getScriptArgs()[1]:"full";
        for(int r=0;r<128;r++)guard(vr(r),r);
        for(int r=0;r<32;r++){guard("r"+r,128+r);guard("vs"+r,160+r);}
        for(String n:new String[]{"crall","xer_so","xer_ov","xer_ov32","xer_ca","xer_ca32","xer_count","LR","CTR","MSR"})guard(n,guards.size());
        if(mode.equals("corpus")) {
            var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonArray();
            for(JsonElement item:rows){var row=item.getAsJsonObject();int w=(int)Long.parseLong(row.get("word").getAsString(),16);
                boolean low=row.get("low").getAsBoolean();int d=row.get("destination").getAsInt(),b=row.get("source").getAsInt();
                for(int k=0;k<16;k++)execute(w,low,d,b,XenonVmxUnpackOracle.pattern(k,w),"real_occurrence");}
        } else {
            if(mode.equals("quick")) {
                for(boolean low:new boolean[]{false,true})for(int[] pair:new int[][]{{37,65},{127,127}})for(int k=0;k<8;k++)
                    execute(XenonVmxUnpackOracle.encoding(low,pair[0],pair[1]),low,pair[0],pair[1],XenonVmxUnpackOracle.pattern(k,0),"quick");
            } else {
                for(boolean low:new boolean[]{false,true})for(int d=0;d<128;d++)for(int b:new int[]{d,(d+37)%128})for(int k=0;k<9;k++)
                    execute(XenonVmxUnpackOracle.encoding(low,d,b),low,d,b,XenonVmxUnpackOracle.pattern(k,d+b),"directed");
                for(boolean low:new boolean[]{false,true})for(int d=0;d<128;d++)for(int b=0;b<128;b++)execute(XenonVmxUnpackOracle.encoding(low,d,b),low,d,b,XenonVmxUnpackOracle.pattern(2,d+b),"all_register_pairs");
                Random rng=new Random(0x5355abcdL);for(int i=0;i<1024;i++){boolean low=rng.nextBoolean();int d=rng.nextInt(128),b=rng.nextInt(128);execute(XenonVmxUnpackOracle.encoding(low,d,b),low,d,b,XenonVmxUnpackOracle.pattern(8+i,i),"random");}
            }
            controls();
        }
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","xenon360/native-unpack-v1");report.put("status","PASS");report.put("mode",mode);
        report.put("pcode_executions",executions);report.put("checks",checks);report.put("coverage",coverage);report.put("selector_controls",controls);
        report.put("guard_registers_per_case",guards.size());report.put("low_bank_aliases_per_case",128);report.put("raw_ops_min",rawMin);report.put("raw_ops_max",rawMax);
        report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));report.put("userop_emulation_callbacks",0);report.put("hardware_equivalence_claimed",false);
        XenonEvidence.writeAtomic(output,report);println("XENON_VMX_UNPACK_PASS executions="+executions+" checks="+checks);
    }
    @Override protected void run()throws Exception {
        try {test();} catch(Throwable failure) {
            XenonEvidence.writeAtomic(Path.of(getScriptArgs()[0]),Map.of("status","FAIL","checks",checks,"pcode_executions",executions,"error",failure.toString()));throw failure;
        }
    }
}
