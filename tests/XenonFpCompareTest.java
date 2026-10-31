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
/** Executes the compiled instruction and subsequent architectural consumers. */
public class XenonFpCompareTest extends GhidraScript {
    static final long PC=0x83000000L;int checks,executions,branches,stale;boolean baseline;
    Map<String,BigInteger> guards=new LinkedHashMap<>();Map<String,Integer> coverage=new TreeMap<>();MessageDigest digest;
    void check(boolean b,String s){checks++;if(!b)throw new AssertionError(s);}
    void test(int word,long a,long b,int initial,String group)throws Exception{
        int cr=(word>>>23)&7,ra=(word>>>16)&31,rb=(word>>>11)&31;if(ra==rb)b=a;
        int want=XenonFpCompareOracle.condition(a,b);String ctx=String.format("%08x %016x %016x initial=%x",word,a,b,initial);
        currentProgram.getMemory().setBytes(toAddr(PC),XenonFpCompareOracle.bytes(word));
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));check(ins!=null&&ins.getMnemonicString().equals("fcmpu"),"decode "+ctx);
        Set<String> outputs=new TreeSet<>();for(var op:ins.getPcode()){
            check(op.getOpcode()!=PcodeOp.CALLOTHER&&op.getOpcode()!=PcodeOp.LOAD&&op.getOpcode()!=PcodeOp.STORE,"register-native");
            var o=op.getOutput();if(o!=null&&!o.isUnique()){
                var r=currentProgram.getRegister(o.getAddress(),o.getSize());check(r!=null,"known register");outputs.add(r.getName());
                check(Set.of("cr"+cr,"fp_cc0","fp_cc1","fp_cc2","fp_cc3").contains(r.getName()),"bounded output "+r.getName());
            }
        }
        if(!baseline)check(outputs.contains("fp_cc3"),"FPCC UN explicit write "+ctx);
        var e=new EmulatorHelper(currentProgram);try{
            Map<String,BigInteger> expected=new LinkedHashMap<>(guards);
            for(var r:guards.entrySet())e.writeRegister(r.getKey(),r.getValue());
            for(int k=0;k<8;k++){var n=BigInteger.valueOf(0xa0|((initial+k)&15));e.writeRegister("cr"+k,n);expected.put("cr"+k,n);}
            for(int k=0;k<4;k++){var n=BigInteger.valueOf((initial>>>(3-k))&1);e.writeRegister("fp_cc"+k,n);expected.put("fp_cc"+k,n);}
            for(int k=0;k<2;k++){var n=BigInteger.valueOf((initial>>>k)&1);e.writeRegister("fp_rn"+k,n);expected.put("fp_rn"+k,n);}
            e.writeRegister("f"+ra,XenonFpCompareOracle.bits(a));expected.put("f"+ra,XenonFpCompareOracle.bits(a));
            e.writeRegister("f"+rb,XenonFpCompareOracle.bits(b));expected.put("f"+rb,XenonFpCompareOracle.bits(b));
            e.writeRegister(e.getPCRegister(),PC);check(e.step(monitor),"execute "+e.getLastError());executions++;
            expected.put("cr"+cr,BigInteger.valueOf(want));
            for(int k=0;k<4;k++)expected.put("fp_cc"+k,BigInteger.valueOf((want>>>(3-k))&1));
            if(baseline){if(e.readRegister("fp_cc3").intValue()!=(want&1))stale++;expected.put("fp_cc3",BigInteger.valueOf(initial&1));}
            for(var r:expected.entrySet())check(e.readRegister(r.getKey()).equals(r.getValue()),"state "+r.getKey()+" "+ctx);
            for(int bit=0;bit<4;bit++){
                long at=PC+16+bit*16;e.writeMemory(toAddr(at),XenonFpCompareOracle.bytes(0x41800008|((cr*4+bit)<<16)));e.writeRegister(e.getPCRegister(),at);
                check(e.step(monitor),"branch");branches++;check(e.readRegister(e.getPCRegister()).longValue()==at+(((want>>(3-bit))&1)!=0?8:4),"branch polarity "+ctx);
            }
            // mcrfs cr7,4 consumes FPCC without clearing exception fields in other FPSCR fields.
            long at=PC+128;e.writeMemory(toAddr(at),XenonFpCompareOracle.bytes(0xff900080));e.writeRegister(e.getPCRegister(),at);
            check(e.step(monitor),"mcrfs consumer");int observed=(want&14)|(baseline?(initial&1):(want&1));check(e.readRegister("cr7").intValue()==observed,"FPCC consumer "+ctx);
            digest.update(XenonFpCompareOracle.bytes(word));digest.update((byte)want);digest.update((byte)observed);
        }finally{e.dispose();}
        coverage.merge(group,1,Integer::sum);coverage.merge(XenonFpCompareOracle.kind(a),1,Integer::sum);coverage.merge(XenonFpCompareOracle.kind(b),1,Integer::sum);
    }
    @Override protected void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);Object owner=new Object();var prior=currentProgram;int tx=-1;
        var lang=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));var p=new ProgramDB("S7-fcmpu-raw",lang,lang.getDefaultCompilerSpec(),owner);
        try{currentProgram=p;tx=p.startTransaction("fixture");p.getMemory().createInitializedBlock("code",toAddr(PC),4096,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);
            digest=MessageDigest.getInstance("SHA-256");String mode=getScriptArgs().length>1?getScriptArgs()[1]:"full";baseline=mode.equals("baseline");
            for(int i=0;i<32;i++){guards.put("f"+i,BigInteger.valueOf(0x123400+i));guards.put("r"+i,BigInteger.valueOf(0x123400+i));}
            for(var r:lang.getRegisters())if(r.getName().startsWith("fp_")||r.getName().startsWith("xer_")||Set.of("VSCR","vscr","LR","CTR","MSR").contains(r.getName()))guards.put(r.getName(),BigInteger.ONE);
            guards.put("fp_ni",BigInteger.ZERO); // NI=1 arithmetic/subnormal behavior remains unqualified.
            long[] vals=XenonFpCompareOracle.VALUES;
            if(mode.equals("corpus")){
                var rows=JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonArray();int n=0;
                for(var item:rows){int w=(int)Long.parseUnsignedLong(item.getAsJsonObject().get("word").getAsString(),16);test(w,vals[n%vals.length],vals[(n*7+3)%vals.length],n++%16,"original_site");}
            }else{
                for(int cr=0;cr<(mode.equals("quick")||baseline?1:8);cr++)for(long a:vals)for(long b:vals)for(int initial:new int[]{0,15})test(XenonFpCompareOracle.word(cr,1,2),a,b,initial,"edge_cross_product");
                if(!mode.equals("quick")&&!baseline)for(int cr=0;cr<8;cr++)for(int a=0;a<32;a++)for(int b=0;b<32;b++)test(XenonFpCompareOracle.word(cr,a,b),vals[(a+cr)%vals.length],vals[(b+5)%vals.length],(a+b+cr)%16,"all_register_aliases");
            }
            if(baseline)check(stale>0,"baseline defect detected");
            XenonEvidence.writeAtomic(out,Map.of("status","PASS","checks",checks,"executions",executions,"branch_executions",branches,"stale_fpcc_un_cases",stale,"coverage",coverage,"result_sha256",HexFormat.of().formatHex(digest.digest()),"contract","FPCC and selected CR only; exception fields preserved as inherited behavior, not validated hardware exception semantics"));println("S7_FP_COMPARE_RAW_PASS "+executions);
        }catch(Throwable e){XenonEvidence.writeAtomic(out,Map.of("status","FAIL","checks",checks,"executions",executions,"error",e.toString()));throw e;}
        finally{if(tx!=-1)p.endTransaction(tx,true);currentProgram=prior;p.release(owner);}
    }
}
