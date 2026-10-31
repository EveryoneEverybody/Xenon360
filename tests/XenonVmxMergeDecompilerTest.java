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
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.XenonEvidence;

/** Mandatory high-p-code oracle: separate source LOADs must reach stored data,
 * and every output byte must match the architectural word mapping. */
public class XenonVmxMergeDecompilerTest extends GhidraScript {
    private int checks,cases;
    private void check(boolean ok,String s){checks++;if(!ok)throw new AssertionError(s);}
    private int memory(int operation,int v,int r){return 4<<26|(v&31)<<21|r<<11|operation<<6|(v>>>5)<<2|3;}
    private int merge(boolean low,int d,int a,int b){return (low?0x18000340:0x18000300)|(d&31)<<21|(a&31)<<16|(b&31)<<11|(d>>>5)<<2|(a&32)|((a&64)<<4)|(b>>>5);}
    private boolean reachesStore(Varnode seed){
        var todo=new ArrayDeque<Varnode>();todo.add(seed);
        Set<Varnode> seen=Collections.newSetFromMap(new IdentityHashMap<>());
        while(!todo.isEmpty()){
            Varnode v=todo.removeFirst();if(!seen.add(v))continue;
            var it=v.getDescendants();while(it.hasNext()){
                PcodeOp op=it.next();if(op.getOpcode()==PcodeOp.STORE&&op.getInput(2)==v)return true;
                if(op.getOutput()!=null&&op.getOpcode()!=PcodeOp.CALLOTHER)todo.add(op.getOutput());
            }
        }return false;
    }
    private BigInteger mask(int bytes){return BigInteger.ONE.shiftLeft(bytes*8).subtract(BigInteger.ONE);}
    private final byte[] aBytes=HexFormat.of().parseHex("0123456789abcdeffedcba9876543210");
    private final byte[] bBytes=HexFormat.of().parseHex("d34a718dc253ee001122bbaa55ff0080");
    private class Evaluator {
        ProgramDB p;int offset;Map<Varnode,BigInteger> memo=new IdentityHashMap<>();Set<Varnode> active=Collections.newSetFromMap(new IdentityHashMap<>());
        Evaluator(ProgramDB program,int unaligned){p=program;offset=unaligned;}
        BigInteger value(Varnode v){
            if(v.isConstant())return new BigInteger(Long.toUnsignedString(v.getOffset())).and(mask(v.getSize()));
            if(memo.containsKey(v))return memo.get(v);
            if(!active.add(v))throw new AssertionError("unexpected high-p-code cycle");
            BigInteger result;PcodeOp op=v.getDef();
            if(op==null){
                result=null;
                for(int r=3;r<=5;r++){
                    var reg=p.getRegister("r"+r);long delta=v.getOffset()-reg.getAddress().getOffset();
                    if(v.getAddress().getAddressSpace().equals(reg.getAddress().getAddressSpace())&&delta>=0&&delta+v.getSize()<=reg.getMinimumByteSize()){
                        long address=r==3?0x1000:r==4?0x2000+offset:0x3000+offset;
                        result=BigInteger.valueOf(address).shiftRight((reg.getMinimumByteSize()-(int)delta-v.getSize())*8);break;
                    }
                }
                if(result==null)throw new AssertionError("unresolved input in stored value/address: "+v);
            }else{
                var x=op.getInputs();
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
                    case PcodeOp.INT_MULT -> value(x[0]).multiply(value(x[1]));
                    case PcodeOp.PTRADD -> value(x[0]).add(value(x[1]).multiply(value(x[2])));
                    case PcodeOp.LOAD -> {
                        long address=value(x[1]).longValueExact();byte[] bytes=new byte[v.getSize()];
                        for(int i=0;i<bytes.length;i++){
                            long at=address+i;byte[] src=at>=0x2000&&at<0x2010?aBytes:at>=0x3000&&at<0x3010?bBytes:null;
                            if(src==null)throw new AssertionError("unexpected high LOAD address "+Long.toHexString(at));
                            bytes[i]=src[(int)(at&15)];
                        }yield new BigInteger(1,bytes);
                    }
                    default -> throw new AssertionError("unsupported high operation in store dependency: "+op);
                };
            }
            result=result.and(mask(v.getSize()));active.remove(v);memo.put(v,result);return result;
        }
    }
    @Override protected void run()throws Exception{
        Path output=Path.of(getScriptArgs()[0]);List<Object> rows=new ArrayList<>();
        String only=getScriptArgs().length>1?getScriptArgs()[1]:"both";
        check(Set.of("both","high","low").contains(only),"valid optional negative-control family");
        var language=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));Object owner=new Object();
        ProgramDB p=new ProgramDB("native-merge-decompiler-regression",language,language.getDefaultCompilerSpec(),owner);
        Map<String,int[]> specs=new LinkedHashMap<>();MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try{
            var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);int tx=p.startTransaction("synthetic functions");
            try{
                p.getMemory().createInitializedBlock("code",start,0x10000,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);int index=0;
                for(int partial:new int[]{0,1})for(boolean low:new boolean[]{false,true})for(int d:new int[]{0,31,32,63,64,95,96,127}){
                    int other=(d+37)%128,third=(d+73)%128;
                    for(int[] ab:new int[][]{{d,other},{other,d},{other,other},{d,d},{other,third},{(d+32)%128,(d+64)%128}}){
                        int a=ab[0],b=ab[1];String name="merge_"+partial+"_"+(low?"low":"high")+"_"+d+"_"+a+"_"+b;
                        var entry=start.add(index++*0x100);int op=partial==0?3:16;
                        byte[] code=ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN).putInt(memory(op,a,4)).putInt(memory(op,b,5)).putInt(merge(low,d,a,b)).putInt(memory(7,d,3)).putInt(0x4e800020).array();
                        p.getMemory().setBytes(entry,code);
                        check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(19)),true).applyTo(p,TaskMonitor.DUMMY),"fixture disassembly "+name);
                        p.getFunctionManager().createFunction(name,entry,new AddressSet(entry,entry.add(19)),SourceType.USER_DEFINED);
                        specs.put(name,new int[]{partial,low?1:0,d,a,b});
                    }
                }
            }finally{p.endTransaction(tx,true);}
            DecompInterface decompiler=new DecompInterface();
            try{
                check(decompiler.openProgram(p),"opens fixture");var functions=p.getFunctionManager().getFunctions(true);
                while(functions.hasNext()){
                    Function f=functions.next();int[] spec=specs.get(f.getName());var result=decompiler.decompileFunction(f,10,monitor);
                    if(!only.equals("both")&&(spec[1]==1?!only.equals("low"):!only.equals("high")))continue;
                    check(result.decompileCompleted()&&result.getHighFunction()!=null,"completed "+f.getName()+": "+result.getErrorMessage());
                    List<PcodeOp> stores=new ArrayList<>();List<String> high=new ArrayList<>(),raw=new ArrayList<>();boolean aDep=false,bDep=false;int opaque=0,loads=0;
                    var ops=result.getHighFunction().getPcodeOps();while(ops.hasNext()){
                        PcodeOp op=ops.next();high.add(op.toString());
                        if(op.getOpcode()==PcodeOp.LOAD){
                            loads++;long at=op.getSeqnum().getTarget().getOffset()-f.getEntryPoint().getOffset();
                            if(at==0)aDep|=reachesStore(op.getOutput());if(at==4)bDep|=reachesStore(op.getOutput());
                        }
                        if(op.getOpcode()==PcodeOp.STORE)stores.add(op);if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;
                    }
                    var instructions=p.getListing().getInstructions(f.getBody(),true);while(instructions.hasNext()){
                        var ins=instructions.next();raw.add(ins.getAddress()+" "+ins+" bytes="+HexFormat.of().formatHex(ins.getBytes()));
                        for(PcodeOp op:ins.getPcode())raw.add(op.toString());
                    }
                    Map<String,Object> row=new LinkedHashMap<>();row.put("function",f.getName());row.put("a_equals_b",spec[3]==spec[4]);
                    row.put("source_a_load_reaches_store",aDep);row.put("source_b_load_reaches_store",bDep);row.put("loads",loads);row.put("stores",stores.size());row.put("opaque",opaque);
                    row.put("c",result.getDecompiledFunction().getC());row.put("raw_pcode",raw);row.put("high_pcode",high);rows.add(row);
                    check(bDep&&(spec[3]==spec[4]?!aDep:aDep),"expected source LOAD dependency "+f.getName());
                    check(opaque==0,"native high-p-code "+f.getName());
                    List<String> storedHex=new ArrayList<>();
                    for(int offset:spec[0]==0?new int[]{0}:new int[]{0,1,3}){
                        Evaluator evaluator=new Evaluator(p,offset);byte[] stored=new byte[16];boolean[] covered=new boolean[16];
                        for(PcodeOp store:stores){
                            long address=evaluator.value(store.getInput(1)).longValueExact();Varnode v=store.getInput(2);BigInteger n=evaluator.value(v);
                            for(int i=0;i<v.getSize();i++){
                                int dst=Math.toIntExact(address-0x1000+i);check(dst>=0&&dst<16&&!covered[dst],"exact output write coverage");
                                covered[dst]=true;stored[dst]=n.shiftRight((v.getSize()-i-1)*8).byteValue();
                            }
                        }
                        byte[] av=new byte[16],bv=new byte[16];System.arraycopy(aBytes,offset,av,0,16-offset);System.arraycopy(bBytes,offset,bv,0,16-offset);
                        if(spec[3]==spec[4])av=bv;byte[] expected=new byte[16];int first=spec[1]==1?8:0;
                        System.arraycopy(av,first,expected,0,4);System.arraycopy(bv,first,expected,4,4);
                        System.arraycopy(av,first+4,expected,8,4);System.arraycopy(bv,first+4,expected,12,4);
                        for(boolean c:covered)check(c,"all stored bytes covered "+f.getName());
                        row.put("expected_hex",HexFormat.of().formatHex(expected));row.put("actual_hex",HexFormat.of().formatHex(stored));
                        check(Arrays.equals(stored,expected),"architectural high-p-code word mapping "+f.getName()+" offset="+offset);
                        storedHex.add(HexFormat.of().formatHex(stored));digest.update(stored);
                    }
                    row.put("stored_vectors",storedHex);row.put("status","PASS");cases++;
                }
            }finally{decompiler.dispose();}
            check(cases==(only.equals("both")?192:96),"all banks, boundaries, alias modes and load forms");
            XenonEvidence.writeAtomic(output,Map.of("schema","xenon360/native-merge-decompiler-v1","status","PASS","checks",checks,"decompiler_cases",cases,"result_sha256",HexFormat.of().formatHex(digest.digest()),"results",rows));
            println("XENON_VMX_MERGE_DECOMPILER_PASS checks="+checks+" cases="+cases);
        }catch(Throwable failure){
            XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"completed_cases",cases,"error",failure.toString(),"results",rows));throw failure;
        }finally{p.release(owner);}
    }
}
