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

/** Evaluate the actual optimized dependency graph from source LOAD to all
 * destination STORE bytes, against the independent guest-byte oracle. */
public class XenonVmxUnpackDecompilerTest extends GhidraScript {
    private int checks,cases,assignments;
    private byte[] input;
    private void check(boolean ok,String m){checks++;if(!ok)throw new AssertionError(m);}
    private BigInteger mask(int bytes){return BigInteger.ONE.shiftLeft(bytes*8).subtract(BigInteger.ONE);}
    private int memory(int op,int v,int r){return 0x10000003|(v&31)<<21|r<<11|op<<6|(v>>>5)<<2;}
    private class Evaluator {
        ProgramDB p;Map<Varnode,BigInteger> memo=new IdentityHashMap<>();Set<Varnode> active=Collections.newSetFromMap(new IdentityHashMap<>());
        Evaluator(ProgramDB p){this.p=p;}
        BigInteger value(Varnode v){
            if(v.isConstant())return new BigInteger(Long.toUnsignedString(v.getOffset())).and(mask(v.getSize()));
            if(memo.containsKey(v))return memo.get(v);
            check(active.add(v),"acyclic optimized dependencies");BigInteger n=null;var op=v.getDef();
            if(op==null){
                for(int r:new int[]{3,4}){var reg=p.getRegister("r"+r);long delta=v.getOffset()-reg.getAddress().getOffset();
                    if(v.getAddress().getAddressSpace().equals(reg.getAddress().getAddressSpace())&&delta>=0&&delta+v.getSize()<=8){n=BigInteger.valueOf(r==3?0x1000:0x2000).shiftRight((8-(int)delta-v.getSize())*8);break;}}
                if(n==null)throw new AssertionError("unresolved optimized input "+v);
            }else{
                var x=op.getInputs();n=switch(op.getOpcode()){
                    case PcodeOp.COPY,PcodeOp.CAST,PcodeOp.INT_ZEXT -> value(x[0]);
                    case PcodeOp.INT_SEXT -> {var a=value(x[0]);yield a.testBit(x[0].getSize()*8-1)?a.subtract(BigInteger.ONE.shiftLeft(x[0].getSize()*8)):a;}
                    case PcodeOp.SUBPIECE -> value(x[0]).shiftRight(value(x[1]).intValueExact()*8);
                    case PcodeOp.PIECE -> value(x[0]).shiftLeft(x[1].getSize()*8).or(value(x[1]));
                    case PcodeOp.INT_LEFT -> value(x[0]).shiftLeft(value(x[1]).intValueExact());
                    case PcodeOp.INT_RIGHT -> value(x[0]).shiftRight(value(x[1]).intValueExact());
                    case PcodeOp.INT_SRIGHT -> {var a=value(x[0]);if(a.testBit(x[0].getSize()*8-1))a=a.subtract(BigInteger.ONE.shiftLeft(x[0].getSize()*8));yield a.shiftRight(value(x[1]).intValueExact());}
                    case PcodeOp.INT_OR -> value(x[0]).or(value(x[1]));
                    case PcodeOp.INT_AND -> value(x[0]).and(value(x[1]));
                    case PcodeOp.INT_XOR -> value(x[0]).xor(value(x[1]));
                    case PcodeOp.INT_ADD,PcodeOp.PTRSUB -> value(x[0]).add(value(x[1]));
                    case PcodeOp.INT_SUB -> value(x[0]).subtract(value(x[1]));
                    case PcodeOp.INT_MULT -> value(x[0]).multiply(value(x[1]));
                    case PcodeOp.PTRADD -> value(x[0]).add(value(x[1]).multiply(value(x[2])));
                    case PcodeOp.LOAD -> {
                        long address=value(x[1]).longValueExact();byte[] bytes=new byte[v.getSize()];
                        for(int i=0;i<bytes.length;i++){long at=address+i;check(at>=0x2000&&at<0x2010,"source byte address");bytes[i]=input[(int)(at-0x2000)];}
                        yield new BigInteger(1,bytes);
                    }
                    default -> throw new AssertionError("unsupported optimized STORE dependency "+op);
                };
            }
            n=n.and(mask(v.getSize()));active.remove(v);memo.put(v,n);return n;
        }
    }
    @Override protected void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]);List<Object> rows=new ArrayList<>();Object owner=new Object();
        var l=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));var p=new ProgramDB("s5-unpack-streams",l,l.getDefaultCompilerSpec(),owner);
        Map<String,int[]> specs=new LinkedHashMap<>();var digest=MessageDigest.getInstance("SHA-256");
        try{
            int tx=p.startTransaction("unpack fixture");var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);
            try{
                p.getMemory().createInitializedBlock("code",start,0x20000,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);int index=0;
                for(boolean low:new boolean[]{false,true})for(int d=0;d<128;d++)for(int b:new int[]{d,(d+37)%128}){
                    String name="unpack_"+index;var entry=start.add(index++*0x100);
                    byte[] code=ByteBuffer.allocate(16).order(ByteOrder.BIG_ENDIAN).putInt(memory(3,b,4)).putInt(XenonVmxUnpackOracle.encoding(low,d,b)).putInt(memory(7,d,3)).putInt(0x4e800020).array();
                    p.getMemory().setBytes(entry,code);check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(15)),true).applyTo(p,TaskMonitor.DUMMY),"fixture decode");
                    p.getFunctionManager().createFunction(name,entry,new AddressSet(entry,entry.add(15)),SourceType.USER_DEFINED);specs.put(name,new int[]{low?1:0,d,b});
                }
            }finally{p.endTransaction(tx,true);}
            var decompiler=new DecompInterface();try{
                check(decompiler.openProgram(p),"open streams");var functions=p.getFunctionManager().getFunctions(true);
                while(functions.hasNext()){
                    var f=functions.next();int[] spec=specs.get(f.getName());long began=System.nanoTime();var result=decompiler.decompileFunction(f,20,monitor);
                    check(result.decompileCompleted()&&result.getHighFunction()!=null,"decompiler completion "+f.getName()+" "+result.getErrorMessage());
                    List<PcodeOp> stores=new ArrayList<>();List<String> high=new ArrayList<>(),raw=new ArrayList<>();int opaque=0,loads=0;
                    var ops=result.getHighFunction().getPcodeOps();while(ops.hasNext()){
                        var op=ops.next();high.add(op.toString());if(op.getOpcode()==PcodeOp.STORE)stores.add(op);
                        if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;if(op.getOpcode()==PcodeOp.LOAD)loads++;
                    }
                    check(opaque==0&&loads>0,"native source LOAD/STORE graph");
                    for(var it=p.getListing().getInstructions(f.getBody(),true);it.hasNext();){var ins=it.next();raw.add(ins.getAddress()+" "+ins+" "+HexFormat.of().formatHex(ins.getBytes()));for(var op:ins.getPcode())raw.add(op.toString());}
                    Path detail=out.resolveSibling(out.getFileName().toString()+".details");Files.createDirectories(detail);
                    Files.writeString(detail.resolve(f.getName()+".c"),result.getDecompiledFunction().getC());
                    Files.writeString(detail.resolve(f.getName()+".high.txt"),String.join("\n",high));
                    Files.writeString(detail.resolve(f.getName()+".raw.txt"),String.join("\n",raw));
                    for(int k=0;k<32;k++){
                        input=XenonVmxUnpackOracle.pattern(k,spec[1]+spec[2]);var ev=new Evaluator(p);byte[] stored=new byte[16];boolean[] covered=new boolean[16];
                        for(var store:stores){long address=ev.value(store.getInput(1)).longValueExact();var v=store.getInput(2);var n=ev.value(v);
                            for(int i=0;i<v.getSize();i++){int dst=Math.toIntExact(address-0x1000+i);check(dst>=0&&dst<16&&!covered[dst],"exact destination write coverage");covered[dst]=true;stored[dst]=n.shiftRight((v.getSize()-i-1)*8).byteValue();}}
                        for(boolean c:covered)check(c,"all destination bytes written");
                        check(Arrays.equals(stored,XenonVmxUnpackOracle.reference(spec[0]==1,input)),"optimized signed-halfword oracle "+f.getName()+" pattern="+k+" actual="+HexFormat.of().formatHex(stored)+" expected="+HexFormat.of().formatHex(XenonVmxUnpackOracle.reference(spec[0]==1,input)));digest.update(stored);assignments++;
                    }
                    Map<String,Object> row=new LinkedHashMap<>();row.put("function",f.getName());row.put("spec",spec);row.put("status","PASS");row.put("opaque",opaque);
                    row.put("c",result.getDecompiledFunction().getC());row.put("raw_pcode",raw);row.put("high_pcode",high);row.put("elapsed_seconds",(System.nanoTime()-began)/1e9);rows.add(row);cases++;
                }
            }finally{decompiler.dispose();}
            check(cases==512&&assignments==16384,"all register and alias streams");
            XenonEvidence.writeAtomic(out,Map.of("schema","xenon360/native-unpack-decompiler-v1","status","PASS","checks",checks,"decompiler_cases",cases,"assignments",assignments,"result_sha256",HexFormat.of().formatHex(digest.digest()),"results",rows));
            println("XENON_VMX_UNPACK_DECOMPILER_PASS cases="+cases+" assignments="+assignments);
        }catch(Throwable failure){XenonEvidence.writeAtomic(out,Map.of("status","FAIL","checks",checks,"completed_cases",cases,"assignments",assignments,"error",failure.toString(),"results",rows));throw failure;}
        finally{p.release(owner);}
    }
}
