import java.math.BigInteger;
import java.nio.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.XenonEvidence;

/** Actual instruction streams and independent evaluation of optimized STORE dependencies. */
public class XenonVmxElementWordDecompilerTest extends GhidraScript {
    private int checks,cases,assignments;
    private long[] registers;
    private byte[] memoryVector;
    private void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
    private BigInteger mask(int bytes){return BigInteger.ONE.shiftLeft(bytes*8).subtract(BigInteger.ONE);}
    private class Evaluator {
        ProgramDB program;
        Map<Varnode,BigInteger> memo=new IdentityHashMap<>();
        Set<Varnode> active=Collections.newSetFromMap(new IdentityHashMap<>());
        Evaluator(ProgramDB p){program=p;}
        BigInteger value(Varnode v){
            if(v.isConstant())return XenonVmxElementWordOracle.unsigned(v.getOffset()).and(mask(v.getSize()));
            if(memo.containsKey(v))return memo.get(v);
            if(!active.add(v))throw new AssertionError("high p-code cycle");
            BigInteger result=null;PcodeOp op=v.getDef();
            if(op==null){
                for(int r=0;r<32;r++){
                    var reg=program.getRegister("r"+r);long delta=v.getOffset()-reg.getAddress().getOffset();
                    if(v.getAddress().getAddressSpace().equals(reg.getAddress().getAddressSpace())&&delta>=0&&delta+v.getSize()<=8){result=XenonVmxElementWordOracle.unsigned(registers[r]).shiftRight((8-(int)delta-v.getSize())*8);break;}
                }
                if(result==null)throw new AssertionError("unresolved stored input "+v);
            }else{
                Varnode[] x=op.getInputs();
                result=switch(op.getOpcode()){
                    case PcodeOp.COPY,PcodeOp.CAST,PcodeOp.INT_ZEXT -> value(x[0]);
                    case PcodeOp.INT_SEXT -> {BigInteger n=value(x[0]);yield n.testBit(x[0].getSize()*8-1)?n.subtract(BigInteger.ONE.shiftLeft(x[0].getSize()*8)):n;}
                    case PcodeOp.SUBPIECE -> value(x[0]).shiftRight(value(x[1]).intValueExact()*8);
                    case PcodeOp.PIECE -> value(x[0]).shiftLeft(x[1].getSize()*8).or(value(x[1]));
                    case PcodeOp.INT_LEFT -> value(x[0]).shiftLeft(value(x[1]).intValueExact());
                    case PcodeOp.INT_RIGHT -> value(x[0]).shiftRight(value(x[1]).intValueExact());
                    case PcodeOp.INT_OR -> value(x[0]).or(value(x[1]));
                    case PcodeOp.INT_AND -> value(x[0]).and(value(x[1]));
                    case PcodeOp.INT_XOR -> value(x[0]).xor(value(x[1]));
                    case PcodeOp.INT_ADD,PcodeOp.PTRSUB -> value(x[0]).add(value(x[1]));
                    case PcodeOp.INT_SUB -> value(x[0]).subtract(value(x[1]));
                    case PcodeOp.INT_NEGATE -> value(x[0]).not();
                    case PcodeOp.INT_2COMP -> value(x[0]).negate();
                    case PcodeOp.INT_MULT -> value(x[0]).multiply(value(x[1]));
                    case PcodeOp.PTRADD -> value(x[0]).add(value(x[1]).multiply(value(x[2])));
                    case PcodeOp.LOAD -> {
                        long address=value(x[1]).longValueExact();byte[] b=new byte[v.getSize()];
                        for(int i=0;i<b.length;i++){long at=address+i;check(at>=0x2000&&at<0x2010,"source memory dependency address");b[i]=memoryVector[(int)(at-0x2000)];}
                        yield new BigInteger(1,b);
                    }
                    default -> throw new AssertionError("unsupported high STORE dependency "+op);
                };
            }
            result=result.and(mask(v.getSize()));active.remove(v);memo.put(v,result);return result;
        }
    }
    private boolean reachesStore(Varnode seed){
        var queue=new ArrayDeque<Varnode>();queue.add(seed);Set<Varnode> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        while(!queue.isEmpty()){var v=queue.removeFirst();if(!seen.add(v))continue;var it=v.getDescendants();while(it.hasNext()){var op=it.next();if(op.getOpcode()==PcodeOp.STORE&&op.getInput(2)==v)return true;if(op.getOpcode()==PcodeOp.COPY&&op.getOutput()!=null&&op.getOutput().getAddress().getAddressSpace().isMemorySpace()&&op.getInput(0)==v)return true;if(op.getOutput()!=null&&op.getOpcode()!=PcodeOp.CALLOTHER)queue.add(op.getOutput());}}
        return false;
    }
    @Override protected void run()throws Exception{
        Path output=Path.of(getScriptArgs()[0]);List<Object> rows=new ArrayList<>();Object owner=new Object();
        var language=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));
        ProgramDB p=new ProgramDB("native-element-word-store-streams",language,language.getDefaultCompilerSpec(),owner);
        Map<String,int[]> specs=new LinkedHashMap<>();MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try{
            var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);int tx=p.startTransaction("instruction streams");
            try{
                p.getMemory().createInitializedBlock("code",start,0x20000,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);
                List<int[]> tuples=new ArrayList<>();
                for(int v=0;v<128;v++)for(int mode=0;mode<2;mode++)tuples.add(new int[]{v,mode==0?0:3,4,0});
                for(int v:new int[]{0,31,32,63,64,95,96,127}){
                    tuples.add(new int[]{v,3,3,0});tuples.add(new int[]{v,0,0,0});
                    for(int lane=0;lane<4;lane++)tuples.add(new int[]{v,0,4,1+lane});
                    tuples.add(new int[]{v,0,4,5});
                }
                int index=0;for(int[] spec:tuples){
                    int v=spec[0],ra=spec[1],rb=spec[2],mode=spec[3];String name="element_word_"+index;var entry=start.add(index++*0x100);
                    List<Integer> words=new ArrayList<>();words.add(XenonVmxElementWordOracle.vectorMemory(3,v,6));
                    // Constants exercise optimized lane extraction. Mode 5 exercises the accepted S1 source result.
                    if(mode>=1&&mode<=4)words.add(0x38800000|0x1000|(mode-1)*4);
                    if(mode==5)words.add(0x18000730|((v&31)<<21)|(1<<16)|((v&31)<<11)|((v>>>5)<<2)|(v>>>5));
                    words.add(XenonVmxElementWordOracle.encoding(v,ra,rb));words.add(0x4e800020);
                    ByteBuffer buffer=ByteBuffer.allocate(words.size()*4).order(ByteOrder.BIG_ENDIAN);for(int w:words)buffer.putInt(w);byte[] code=buffer.array();p.getMemory().setBytes(entry,code);
                    check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(code.length-1)),true).applyTo(p,TaskMonitor.DUMMY),"stream disassembly");
                    p.getFunctionManager().createFunction(name,entry,new AddressSet(entry,entry.add(code.length-1)),SourceType.USER_DEFINED);specs.put(name,spec);
                }
            }finally{p.endTransaction(tx,true);}
            DecompInterface d=new DecompInterface();
            try{
                check(d.openProgram(p),"decompiler opens streams");var functions=p.getFunctionManager().getFunctions(true);
                while(functions.hasNext()){
                    var f=functions.next();int[] spec=specs.get(f.getName());var result=d.decompileFunction(f,20,monitor);
                    check(result.decompileCompleted()&&result.getHighFunction()!=null,"decompile completed "+f.getName()+" "+result.getErrorMessage());
                    List<PcodeOp> stores=new ArrayList<>();List<String> high=new ArrayList<>(),raw=new ArrayList<>();boolean dependency=false;int opaque=0,storeOpcodes=0;
                    var targetAddress=f.getEntryPoint().add(spec[3]==0?4:8);
                    var ops=result.getHighFunction().getPcodeOps();while(ops.hasNext()){
                        var op=ops.next();high.add(op.getSeqnum()+" "+op);if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;
                        if(op.getOpcode()==PcodeOp.STORE){stores.add(op);storeOpcodes++;}
                        // Constant STOREs become a COPY to a RAM varnode. Exclude
                        // decompiler bookkeeping copies at other instruction addresses.
                        if(op.getOpcode()==PcodeOp.COPY&&op.getOutput()!=null&&op.getOutput().getAddress().getAddressSpace().isMemorySpace()&&op.getSeqnum().getTarget().equals(targetAddress))stores.add(op);
                        if(op.getOpcode()==PcodeOp.LOAD)dependency|=reachesStore(op.getOutput());
                    }
                    var instructions=p.getListing().getInstructions(f.getBody(),true);while(instructions.hasNext()){var ins=instructions.next();raw.add(ins.getAddress()+" "+ins+" bytes="+HexFormat.of().formatHex(ins.getBytes()));for(var op:ins.getPcode())raw.add(op.toString());}
                    Map<String,Object> row=new LinkedHashMap<>();rows.add(row);row.put("function",f.getName());row.put("spec",spec);row.put("c",result.getDecompiledFunction().getC());row.put("raw_pcode",raw);row.put("high_pcode",high);row.put("source_load_reaches_store",dependency);row.put("architectural_memory_writes",stores.size());row.put("store_opcodes",storeOpcodes);row.put("opaque",opaque);
                    check(opaque==0,"native optimized semantics");check(stores.size()==1,"one optimized architectural memory write survives");
                    var write=stores.get(0);var writtenValue=write.getInput(write.getOpcode()==PcodeOp.STORE?2:0);
                    check(writtenValue.getSize()==4,"optimized STORE width four");check(dependency,"source LOAD reaches selected STORE value");
                    List<Object> samples=new ArrayList<>();row.put("samples",samples);
                    for(int nibble=0;nibble<16;nibble++)for(int pattern=0;pattern<6;pattern++){
                        registers=new long[32];Arrays.fill(registers,0x12345678L);registers[6]=0x2000;registers[0]=0x12341000L+nibble;registers[3]=0xfffffff0L;registers[4]=0x12341010L+nibble;
                        if(spec[1]==3&&spec[2]==3)registers[3]=0x891a0800L+nibble;
                        if(spec[3]>=1&&spec[3]<=4)registers[4]=0x1000+(spec[3]-1)*4;
                        memoryVector=XenonVmxElementWordOracle.pattern(pattern,cases+nibble);byte[] source=memoryVector;
                        if(spec[3]==5){source=new byte[16];for(int lane=0;lane<4;lane++)System.arraycopy(memoryVector,4,source,lane*4,4);}
                        var expected=XenonVmxElementWordOracle.reference(spec[1],spec[2],registers,source);Evaluator evaluator=new Evaluator(p);var store=stores.get(0);
                        long address=store.getOpcode()==PcodeOp.STORE?evaluator.value(store.getInput(1)).longValueExact():store.getOutput().getOffset();BigInteger value=evaluator.value(writtenValue);byte[] bytes=new byte[4];for(int i=0;i<4;i++)bytes[i]=value.shiftRight((3-i)*8).byteValue();
                        check(address==expected.storeAddress(),"optimized architectural STORE address");check(Arrays.equals(bytes,expected.bytes()),"optimized architectural STORE bytes");
                        digest.update(bytes);digest.update(BigInteger.valueOf(address).toByteArray());assignments++;
                        if(pattern==0)samples.add(Map.of("nibble",nibble,"address",address,"source",HexFormat.of().formatHex(source),"expected",HexFormat.of().formatHex(expected.bytes()),"actual",HexFormat.of().formatHex(bytes)));
                    }
                    row.put("status","PASS");cases++;
                }
            }finally{d.dispose();}
            check(cases==312,"all stream fixtures");
            XenonEvidence.writeAtomic(output,Map.of("status","PASS","schema","xenon360/native-element-word-decompiler-v1","checks",checks,"decompiler_cases",cases,"assignments",assignments,"result_sha256",HexFormat.of().formatHex(digest.digest()),"results",rows));
            println("XENON_VMX_ELEMENT_WORD_DECOMPILER_PASS cases="+cases+" assignments="+assignments);
        }catch(Throwable failure){XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"completed_cases",cases,"assignments",assignments,"error",failure.toString(),"results",rows));throw failure;}
        finally{p.release(owner);}
    }
}
