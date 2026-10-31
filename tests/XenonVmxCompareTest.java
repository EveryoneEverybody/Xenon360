import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import com.google.gson.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.XenonEvidence;
/** Direct execution of compiled p-code, not an emulated CALLOTHER callback. */
public class XenonVmxCompareTest extends GhidraScript {
    static final long PC=0x83000000L;int checks,executions,branches;Map<String,Integer> coverage=new TreeMap<>();
    Map<String,BigInteger> guards=new LinkedHashMap<>();MessageDigest digest;
    void check(boolean b,String s){checks++;if(!b)throw new AssertionError(s);}
    void test(int word,int mask,int pattern,String group)throws Exception{
        int[] r=XenonVmxCompareOracle.registers(word);boolean record=(word&64)!=0;
        byte[] a=XenonVmxCompareOracle.operand(pattern),b=XenonVmxCompareOracle.peer(a,mask);
        if(r[1]==r[2])b=a.clone();
        byte[] expected=XenonVmxCompareOracle.vector(a,b);String context=String.format("%08x mask=%x pattern=%d",word,mask,pattern);
        byte[] bytes=XenonVmxCompareOracle.instruction(word);currentProgram.getMemory().setBytes(toAddr(PC),bytes);
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        check(ins!=null&&ins.toString().equals("vcmpequw128"+(record?".":"")+" v"+r[0]+",v"+r[1]+",v"+r[2]),"decode "+context);
        for(var op:ins.getPcode()){
            check(op.getOpcode()!=PcodeOp.CALLOTHER&&op.getOpcode()!=PcodeOp.STORE&&op.getOpcode()!=PcodeOp.LOAD,"native register-only "+context);
            var v=op.getOutput();if(v!=null&&!v.isUnique()){
                var d=currentProgram.getRegister(XenonVmxCompareOracle.register(r[0]));var cr=currentProgram.getRegister("cr6");
                check(v.isRegister()&&((v.getAddress().equals(d.getAddress())&&v.getSize()==16)||(record&&v.getAddress().equals(cr.getAddress())&&v.getSize()==1)),"bounded writes "+op);
            }
        }
        var e=new EmulatorHelper(currentProgram);try{
            Map<String,BigInteger> want=new LinkedHashMap<>(guards);
            for(var g:guards.entrySet())e.writeRegister(g.getKey(),g.getValue());
            for(int i=0;i<8;i++){BigInteger c=BigInteger.valueOf(((i+pattern)%16)|0xa0);e.writeRegister("cr"+i,c);want.put("cr"+i,c);}
            e.writeRegister(XenonVmxCompareOracle.register(r[1]),new BigInteger(1,a));want.put(XenonVmxCompareOracle.register(r[1]),new BigInteger(1,a));
            e.writeRegister(XenonVmxCompareOracle.register(r[2]),new BigInteger(1,b));want.put(XenonVmxCompareOracle.register(r[2]),new BigInteger(1,b));
            e.writeRegister(e.getPCRegister(),PC);check(e.step(monitor),"execution "+context+" "+e.getLastError());executions++;
            want.put(XenonVmxCompareOracle.register(r[0]),new BigInteger(1,expected));
            if(record)want.put("cr6",BigInteger.valueOf(0xa0|XenonVmxCompareOracle.cr6(expected)));
            for(var g:want.entrySet())check(e.readRegister(g.getKey()).equals(g.getValue()),"state "+g.getKey()+" "+context+" actual="+e.readRegister(g.getKey()).toString(16)+" expected="+g.getValue().toString(16));
            check(e.readRegister(e.getPCRegister()).longValue()==PC+4,"PC");
            // Consume every CR6 bit through real conditional-branch p-code.
            for(int bit=0;bit<4;bit++){
                long branchPC=PC+4+bit*16;int branch=0x41800008|((24+bit)<<16);
                e.writeMemory(toAddr(branchPC),XenonVmxCompareOracle.instruction(branch));e.writeRegister(e.getPCRegister(),branchPC);
                check(e.step(monitor),"branch executes");branches++;
                boolean taken=want.get("cr6").testBit(3-bit);
                check(e.readRegister(e.getPCRegister()).longValue()==branchPC+(taken?8:4),"CR6 branch bit "+bit+" "+context);
            }
            digest.update(bytes);digest.update(a);digest.update(b);digest.update(expected);digest.update((byte)want.get("cr6").intValue());
        }finally{e.dispose();}
        coverage.merge(group,1,Integer::sum);coverage.merge(record?"record":"nonrecord",1,Integer::sum);
    }
    @Override protected void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);Object owner=new Object();var previous=currentProgram;
        var lang=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));var p=new ProgramDB("S6-direct",lang,lang.getDefaultCompilerSpec(),owner);
        int testTransaction=-1;
        try{currentProgram=p;int tx=p.startTransaction("fixture");try{p.getMemory().createInitializedBlock("code",toAddr(PC),4096,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);}finally{p.endTransaction(tx,true);}
            testTransaction=p.startTransaction("instruction executions");
            digest=MessageDigest.getInstance("SHA-256");
            for(int i=0;i<128;i++)guards.put(XenonVmxCompareOracle.register(i),new BigInteger(1,XenonVmxCompareOracle.operand(i%16)));
            for(int i=0;i<32;i++){guards.put("r"+i,BigInteger.valueOf(0x1000L+i*71));guards.put("vs"+i,BigInteger.valueOf(0x1200L+i));}
            for(var reg:lang.getRegisters())if(reg.getName().startsWith("fp_")||reg.getName().startsWith("xer_")||Set.of("VSCR","vscr","LR","CTR","MSR").contains(reg.getName()))guards.put(reg.getName(),BigInteger.ONE);
            if(getScriptArgs().length>1&&getScriptArgs()[1].equals("corpus")){
                var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonArray();
                for(var item:rows){int w=(int)Long.parseLong(item.getAsJsonObject().get("word").getAsString(),16);for(int mask=0;mask<16;mask++)test(w,mask,mask,"original_occurrence");}
            }else{
                boolean quick=getScriptArgs().length>1&&getScriptArgs()[1].equals("quick");
                for(boolean rec:new boolean[]{false,true})for(int[] regs:new int[][]{{37,65,99},{127,127,2},{0,31,0},{63,63,63},{32,32,64}})for(int mask=0;mask<16;mask++)for(int k=0;k<(quick?1:16);k++)test(XenonVmxCompareOracle.encoding(rec,regs[0],regs[1],regs[2]),mask,k,"masks_boundaries_aliases");
                if(!quick)for(boolean rec:new boolean[]{false,true})for(int a=0;a<128;a++)for(int b=0;b<128;b++)test(XenonVmxCompareOracle.encoding(rec,(a+b*7)%128,a,b),(a+b)%16,(a+b)%16,"all_source_register_pairs");
            }
            XenonEvidence.writeAtomic(out,Map.of("status","PASS","checks",checks,"executions",executions,"branch_executions",branches,"coverage",coverage,"result_sha256",HexFormat.of().formatHex(digest.digest()),"opaque_callbacks",0));
            println("S6_COMPARE_RAW_PASS "+executions);
        }catch(Throwable e){XenonEvidence.writeAtomic(out,Map.of("status","FAIL","checks",checks,"executions",executions,"error",e.toString()));throw e;}
        finally{if(testTransaction!=-1)p.endTransaction(testTransaction,true);currentProgram=previous;p.release(owner);}
    }
}
