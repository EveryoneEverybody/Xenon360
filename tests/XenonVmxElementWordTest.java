import java.math.BigInteger;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.pcode.PcodeOp;
import xenon360.analysis.XenonEvidence;

/** Execute emitted p-code; check exact write set, guest bytes, and architectural guards. */
public class XenonVmxElementWordTest extends GhidraScript {
    private static final long PC=0x82001240L;
    private int checks,executions,minOps=Integer.MAX_VALUE,maxOps;
    private final Map<String,BigInteger> guards=new LinkedHashMap<>();
    private final Map<String,Integer> coverage=new TreeMap<>();
    private final Set<Integer> vectors=new TreeSet<>(),nibbles=new TreeSet<>(),ras=new TreeSet<>(),rbs=new TreeSet<>();
    private final List<Object> samples=new ArrayList<>();
    private Map<String,Object> last=new LinkedHashMap<>();
    private final MessageDigest digest;
    public XenonVmxElementWordTest()throws Exception{digest=MessageDigest.getInstance("SHA-256");}
    private void check(boolean ok,String text){checks++;if(!ok)throw new AssertionError(text);}
    private void guard(String name,int seed){var r=currentProgram.getRegister(name);check(r!=null,"guard "+name);byte[] b=new byte[r.getMinimumByteSize()];for(int i=0;i<b.length;i++)b[i]=(byte)(seed*17+i*13+0x51);guards.put(name,new BigInteger(1,b));}
    private long[] gprs(){long[] r=new long[32];for(int i=0;i<32;i++)r[i]=0x71922344abcde000L+i*37;return r;}
    private void execute(String group,int v,int ra,int rb,long[] regs,byte[] vector)throws Exception{
        var expected=XenonVmxElementWordOracle.reference(ra,rb,regs,vector);
        byte[] code=XenonVmxElementWordOracle.instruction(XenonVmxElementWordOracle.encoding(v,ra,rb));
        last=new LinkedHashMap<>();last.put("group",group);last.put("vector_register",v);last.put("ra",ra);last.put("rb",rb);last.put("ra_value",Long.toUnsignedString(regs[ra],16));last.put("rb_value",Long.toUnsignedString(regs[rb],16));
        last.put("vector",HexFormat.of().formatHex(vector));last.put("raw_ea_64",expected.raw64().toString(16));last.put("effective_32",expected.effective32());last.put("store_address",expected.storeAddress());last.put("word_index",expected.wordIndex());last.put("expected",HexFormat.of().formatHex(expected.bytes()));last.put("encoding",HexFormat.of().formatHex(code));
        currentProgram.getMemory().setBytes(toAddr(PC),code);
        var ins=new PseudoDisassembler(currentProgram).disassemble(toAddr(PC));
        check(ins!=null&&ins.getMnemonicString().equals("stvewx128"),"target decoding");
        check(ins.getLength()==4&&ins.getFlowType().isFallthrough(),"instruction shape");
        check(ins.getDefaultOperandRepresentation(0).equals("v"+v),"extended source operand");
        check(ins.getDefaultOperandRepresentation(1).equals(ra==0?"0":"r"+ra),"RA convention decode");
        check(ins.getDefaultOperandRepresentation(2).equals("r"+rb),"RB decode");
        int stores=0;for(PcodeOp op:ins.getPcode()){
            check(op.getOpcode()!=PcodeOp.CALLOTHER,"no opaque operation");
            if(op.getOpcode()==PcodeOp.STORE){stores++;check(op.getInput(2).getSize()==4,"architectural STORE width four");}
            check(op.getOpcode()!=PcodeOp.LOAD,"no architectural memory read");
            if(op.getOutput()!=null)check(op.getOutput().isUnique(),"no architectural register writes");
        }check(stores==1,"exactly one architectural STORE");
        minOps=Math.min(minOps,ins.getPcode().length);maxOps=Math.max(maxOps,ins.getPcode().length);
        EmulatorHelper emulator=new EmulatorHelper(currentProgram);
        try{
            for(var entry:guards.entrySet())emulator.writeRegister(entry.getKey(),entry.getValue());
            for(int r=0;r<32;r++)emulator.writeRegister("r"+r,XenonVmxElementWordOracle.unsigned(regs[r]));
            emulator.writeRegister(XenonVmxElementWordOracle.register(v),new BigInteger(1,vector));
            emulator.writeRegister(emulator.getPCRegister(),PC);
            for(int i=-16;i<20;i++)emulator.writeMemory(toAddr((expected.storeAddress()+i)&0xffffffffL),new byte[]{(byte)0x6d});
            emulator.enableMemoryWriteTracking(true);
            check(emulator.step(monitor),"native execution: "+emulator.getLastError());executions++;
            byte[] actual=emulator.readMemory(toAddr(expected.storeAddress()),4);last.put("actual",HexFormat.of().formatHex(actual));
            check(Arrays.equals(expected.bytes(),actual),"architectural guest memory bytes");
            var writes=emulator.getTrackedMemoryWriteSet();
            // EmulatorHelper also tracks internal unique/register space writes, including PC.
            // Architectural memory extent is specifically the guest RAM intersection.
            last.put("all_tracked_writes",writes.toString());
            var ramWrites=writes.intersectRange(toAddr(0),toAddr(0xffffffffL));
            last.put("ram_tracked_writes",ramWrites.toString());
            check(ramWrites.getNumAddresses()==4&&ramWrites.contains(toAddr(expected.storeAddress()),toAddr(expected.storeAddress()+3)),"architectural memory write extent/address");
            for(int i=-16;i<20;i++)if(i<0||i>=4)check(emulator.readMemoryByte(toAddr((expected.storeAddress()+i)&0xffffffffL))==(byte)0x6d,"adjacent sentinel preserved");
            for(var entry:guards.entrySet()){
                BigInteger value=entry.getValue();String n=entry.getKey();
                if(n.equals(XenonVmxElementWordOracle.register(v)))value=new BigInteger(1,vector);
                if(n.matches("r[0-9]+"))value=XenonVmxElementWordOracle.unsigned(regs[Integer.parseInt(n.substring(1))]);
                check(emulator.readRegister(n).equals(value),"register unchanged "+n);
            }
            if(v<32)for(int lane=0;lane<4;lane++){
                BigInteger word=new BigInteger(1,Arrays.copyOfRange(vector,lane*4,lane*4+4));
                check(emulator.readRegister("vr"+v+"_32_"+lane).equals(word),"Ghidra big-endian lane alias "+lane);
            }
            check(emulator.readRegister(emulator.getPCRegister()).longValue()==PC+4,"PC advances four");
            check(Arrays.equals(code,emulator.readMemory(toAddr(PC),4)),"code unchanged");
            digest.update(code);digest.update(vector);digest.update(expected.raw64().toByteArray());digest.update(actual);
        }finally{emulator.dispose();}
        if(samples.size()<32||group.equals("boundary"))samples.add(new LinkedHashMap<>(last));
        vectors.add(v);ras.add(ra);rbs.add(rb);nibbles.add((int)(expected.effective32()%16));coverage.merge(group,1,Integer::sum);
    }
    @Override protected void run()throws Exception{
        Path output=Path.of(getScriptArgs()[0]);
        try{
            check(currentProgram.getAddressFactory().getDefaultAddressSpace().getSize()==32,"language truncates ram to 32 bits");
            for(int r=0;r<128;r++)guard(XenonVmxElementWordOracle.register(r),r);
            for(int r=0;r<32;r++){guard("r"+r,128+r);guard("vs"+r,160+r);}
            for(String n:new String[]{"crall","xer_so","xer_ov","xer_ov32","xer_ca","xer_ca32","xer_count","LR","CTR","MSR"})guard(n,guards.size());
            for(int v=0;v<128;v++)for(int nibble=0;nibble<16;nibble++)for(int pattern=0;pattern<6;pattern++){
                long[] r=gprs();r[3]=0x81234560L+nibble;execute("all_vectors_nibbles_patterns_ra0",v,0,3,r,XenonVmxElementWordOracle.pattern(pattern,v));
            }
            for(int ra=0;ra<32;ra++)for(int rb=0;rb<32;rb++)for(int nibble=0;nibble<16;nibble+=3){
                long[] r=gprs();r[ra]=0xfffffff0L;r[rb]=0x12345670L+nibble;
                execute("gpr_pairs",(ra*7+rb*11)%128,ra,rb,r,XenonVmxElementWordOracle.pattern(0,ra+rb));
            }
            long[][] addresses={{0,0},{0,1},{0,3},{0,15},{0,0xffffffffL},{0xffffffffL,1},{0xfffffffeL,7},{0x7fffffffL,1},{0x100000000L,0x1234567bL},{-1L,1},{-8L,15},{0x123456789abcdef0L,0xfedcba987654321fL},{0x00fffffcL,16}};
            for(int v:new int[]{0,31,32,63,64,95,96,127})for(long[] pair:addresses)for(int ra:new int[]{0,3}){
                long[] r=gprs();r[3]=pair[0];r[4]=pair[1];execute("boundary",v,ra,4,r,XenonVmxElementWordOracle.pattern(0,v));
            }
            Random random=new Random(0x5354345f524e47L);
            for(int i=0;i<512;i++){long[] r=gprs();for(int j=0;j<32;j++)r[j]=random.nextLong();byte[] b=new byte[16];random.nextBytes(b);execute("random",random.nextInt(128),random.nextInt(32),random.nextInt(32),r,b);}
            check(vectors.size()==128&&nibbles.size()==16&&ras.size()==32&&rbs.size()==32,"complete register/nibble coverage");
            Map<String,Object> report=new LinkedHashMap<>();report.put("status","PASS");report.put("schema","xenon360/native-element-word-v1");report.put("checks",checks);report.put("pcode_executions",executions);report.put("coverage",coverage);report.put("vectors",vectors);report.put("low_nibbles",nibbles);report.put("ra_encodings",ras);report.put("rb_encodings",rbs);report.put("guard_registers_per_case",guards.size());report.put("raw_ops_min",minOps);report.put("raw_ops_max",maxOps);report.put("result_sha256",HexFormat.of().formatHex(digest.digest()));report.put("samples",samples);report.put("userop_emulation_callbacks",0);
            XenonEvidence.writeAtomic(output,report);println("XENON_VMX_ELEMENT_WORD_PASS executions="+executions+" checks="+checks);
        }catch(Throwable failure){XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"pcode_executions",executions,"error",failure.toString(),"last",last));throw failure;}
    }
}
