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
/** Evaluate optimized scalar FPCC dataflow against an independent bit oracle. */
public class XenonFpCompareDecompilerTest extends GhidraScript {
    int checks,cases,assignments;byte[] inA,inB;long initialCR;
    void check(boolean b,String s){checks++;if(!b)throw new AssertionError(s);}
    BigInteger mask(int n){return BigInteger.ONE.shiftLeft(n*8).subtract(BigInteger.ONE);}
    int memory(int op,int v,int r){return 0x10000003|(v&31)<<21|r<<11|op<<6|(v>>>5)<<2;}
    class Evaluator {
        ProgramDB p;Map<Varnode,BigInteger> memo=new IdentityHashMap<>();Set<Varnode> active=Collections.newSetFromMap(new IdentityHashMap<>());
        Evaluator(ProgramDB p){this.p=p;}
        BigInteger value(Varnode v){
            if(v.isConstant())return new BigInteger(Long.toUnsignedString(v.getOffset())).and(mask(v.getSize()));
            if(memo.containsKey(v))return memo.get(v);check(active.add(v),"acyclic");BigInteger n=null;var op=v.getDef();
            if(op==null){
                for(int r:new int[]{3,4,5,7}){var reg=p.getRegister("r"+r);long delta=v.getOffset()-reg.getAddress().getOffset();
                    if(v.getAddress().getAddressSpace().equals(reg.getAddress().getAddressSpace())&&delta>=0&&delta+v.getSize()<=8){n=BigInteger.valueOf(r==3?0x1000:r==4?0x2000:r==5?0x3000:initialCR).shiftRight((8-(int)delta-v.getSize())*8);break;}}
                if(n==null)throw new AssertionError("unresolved input "+v);
            }else{var x=op.getInputs();n=switch(op.getOpcode()){
                case PcodeOp.FLOAT_NAN -> Double.isNaN(Double.longBitsToDouble(value(x[0]).longValue()))?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.FLOAT_EQUAL -> Double.longBitsToDouble(value(x[0]).longValue())==Double.longBitsToDouble(value(x[1]).longValue())?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.FLOAT_NOTEQUAL -> Double.longBitsToDouble(value(x[0]).longValue())!=Double.longBitsToDouble(value(x[1]).longValue())?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.FLOAT_LESS -> Double.longBitsToDouble(value(x[0]).longValue())<Double.longBitsToDouble(value(x[1]).longValue())?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.FLOAT_LESSEQUAL -> Double.longBitsToDouble(value(x[0]).longValue())<=Double.longBitsToDouble(value(x[1]).longValue())?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.COPY,PcodeOp.CAST,PcodeOp.INT_ZEXT -> value(x[0]);
                case PcodeOp.INT_SEXT -> {var a=value(x[0]);yield a.testBit(x[0].getSize()*8-1)?a.subtract(BigInteger.ONE.shiftLeft(x[0].getSize()*8)):a;}
                case PcodeOp.SUBPIECE -> value(x[0]).shiftRight(value(x[1]).intValueExact()*8);
                case PcodeOp.PIECE -> value(x[0]).shiftLeft(x[1].getSize()*8).or(value(x[1]));
                case PcodeOp.INT_LEFT -> value(x[0]).shiftLeft(value(x[1]).intValueExact());
                case PcodeOp.INT_RIGHT -> value(x[0]).shiftRight(value(x[1]).intValueExact());
                case PcodeOp.INT_SRIGHT -> {var a=value(x[0]);if(a.testBit(x[0].getSize()*8-1))a=a.subtract(BigInteger.ONE.shiftLeft(x[0].getSize()*8));yield a.shiftRight(value(x[1]).intValueExact());}
                case PcodeOp.INT_OR,PcodeOp.BOOL_OR -> value(x[0]).or(value(x[1]));
                case PcodeOp.INT_AND,PcodeOp.BOOL_AND -> value(x[0]).and(value(x[1]));
                case PcodeOp.INT_XOR,PcodeOp.BOOL_XOR -> value(x[0]).xor(value(x[1]));
                case PcodeOp.INT_NEGATE -> value(x[0]).xor(mask(v.getSize()));
                case PcodeOp.INT_2COMP -> value(x[0]).negate();
                case PcodeOp.BOOL_NEGATE -> value(x[0]).signum()==0?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.INT_EQUAL -> value(x[0]).equals(value(x[1]))?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.INT_NOTEQUAL -> !value(x[0]).equals(value(x[1]))?BigInteger.ONE:BigInteger.ZERO;
                case PcodeOp.INT_ADD,PcodeOp.PTRSUB -> value(x[0]).add(value(x[1]));
                case PcodeOp.INT_SUB -> value(x[0]).subtract(value(x[1]));
                case PcodeOp.INT_MULT -> value(x[0]).multiply(value(x[1]));
                case PcodeOp.PTRADD -> value(x[0]).add(value(x[1]).multiply(value(x[2])));
                case PcodeOp.LOAD -> {long at=value(x[1]).longValueExact();byte[] a=at>=0x3000?inB:inA;int offset=(int)(at-(at>=0x3000?0x3000:0x2000));check(offset>=0&&offset+v.getSize()<=16,"source load");yield new BigInteger(1,Arrays.copyOfRange(a,offset,offset+v.getSize()));}
                default -> throw new AssertionError("unsupported optimized op "+op);
            };}
            n=n.and(mask(v.getSize()));active.remove(v);memo.put(v,n);return n;
        }
    }
    @Override protected void run()throws Exception{
        Path out=Path.of(getScriptArgs()[0]),detail=out.resolveSibling(out.getFileName()+".details");Files.createDirectories(detail);
        Object owner=new Object();var l=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));var p=new ProgramDB("S7-optimized",l,l.getDefaultCompilerSpec(),owner);
        List<Object> rows=new ArrayList<>();Map<String,int[]> specs=new LinkedHashMap<>();var digest=MessageDigest.getInstance("SHA-256");
        boolean baseline=getScriptArgs().length>1&&getScriptArgs()[1].equals("baseline");
        boolean original=getScriptArgs().length>1&&getScriptArgs()[1].equals("corpus");
        try{
            List<Integer> inputs=new ArrayList<>();
            if(original){var json=com.google.gson.JsonParser.parseString(Files.readString(Path.of(getScriptArgs()[2]))).getAsJsonArray();var unique=new TreeSet<Integer>();for(var item:json)unique.add((int)Long.parseUnsignedLong(item.getAsJsonObject().get("word").getAsString(),16));inputs.addAll(unique);}
            else for(int cr=0;cr<8;cr++)for(int[] regs:new int[][]{{1,2},{0,0},{31,1},{1,31}})inputs.add(XenonFpCompareOracle.word(cr,regs[0],regs[1]));
            int tx=p.startTransaction("fixture");
            try{var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);p.getMemory().createInitializedBlock("code",start,Math.max(0x10000,inputs.size()*512),(byte)0,TaskMonitor.DUMMY,false).setExecute(true);int index=0;
                for(int w:inputs)for(int initial:new int[]{0,15}){
                    int a=(w>>>16)&31,b=(w>>>11)&31,cr=(w>>>23)&7;
                    // Loads, initialize CR and FPSCR.FU, original fcmpu, mcrfs cr7,4, mfcr/store.
                    int[] words={0xc8000000|(a<<21)|(4<<16),0xc8000000|(b<<21)|(5<<16),0x7ceff120,initial==0?0xfe60008c:0xfe60004c,w,0xff900080,0x7cc00026,0x90c30000,0x4e800020};
                    var code=ByteBuffer.allocate(words.length*4).order(ByteOrder.BIG_ENDIAN);for(int v:words)code.putInt(v);
                    var entry=start.add(index*0x100L);String name="fpcompare_"+index++;p.getMemory().setBytes(entry,code.array());check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(code.capacity()-1)),true).applyTo(p,TaskMonitor.DUMMY),"decode fixture");
                    p.getFunctionManager().createFunction(name,entry,new AddressSet(entry,entry.add(code.capacity()-1)),SourceType.USER_DEFINED);specs.put(name,new int[]{w,initial,cr,a,b});
                }
            }finally{p.endTransaction(tx,true);}
            var dec=new DecompInterface();try{check(dec.openProgram(p),"open");
                for(var it=p.getFunctionManager().getFunctions(true);it.hasNext();){var f=it.next();int[] spec=specs.get(f.getName());var result=dec.decompileFunction(f,30,monitor);check(result.decompileCompleted()&&result.getHighFunction()!=null,"complete "+result.getErrorMessage());
                    List<PcodeOp> stores=new ArrayList<>();List<String> high=new ArrayList<>();int opaque=0;
                    for(var ops=result.getHighFunction().getPcodeOps();ops.hasNext();){var op=ops.next();high.add(op.toString());if(op.getOpcode()==PcodeOp.STORE)stores.add(op);if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;}
                    check(opaque==0,"native optimized result");Files.writeString(detail.resolve(f.getName()+".c"),result.getDecompiledFunction().getC());Files.writeString(detail.resolve(f.getName()+".high.txt"),String.join("\n",high));
                    long[] values=XenonFpCompareOracle.VALUES;
                    for(int k=0;k<(original?8:values.length*values.length);k++){
                        long a=values[original?k%values.length:k/values.length],b=values[original?(k*7+19)%values.length:k%values.length];
                        inA=ByteBuffer.allocate(16).putLong(a).array();inB=ByteBuffer.allocate(16).putLong(b).array();initialCR=0x12345678L^(k*0x11111111L);initialCR&=0xffffffffL;
                        int condition=XenonFpCompareOracle.condition(spec[3]==spec[4]?b:a,b),observed=(condition&14)|(baseline?(spec[1]&1):(condition&1));
                        int shift=(7-spec[2])*4;long cr=(initialCR&~(15L<<shift))|((long)condition<<shift);cr=(cr&~15L)|observed;
                        byte[] wanted=ByteBuffer.allocate(4).putInt((int)cr).array(),actual=new byte[4];boolean[] covered=new boolean[4];var ev=new Evaluator(p);
                        for(var store:stores){int dst=Math.toIntExact(ev.value(store.getInput(1)).longValueExact()-0x1000);var v=store.getInput(2);var n=ev.value(v);for(int j=0;j<v.getSize();j++){check(dst+j>=0&&dst+j<4&&!covered[dst+j],"write extent");covered[dst+j]=true;actual[dst+j]=n.shiftRight((v.getSize()-j-1)*8).byteValue();}}
                        for(boolean b0:covered)check(b0,"full write coverage");check(Arrays.equals(wanted,actual),"optimized oracle "+f.getName()+" case="+k+" actual="+HexFormat.of().formatHex(actual)+" expected="+HexFormat.of().formatHex(wanted));digest.update(actual);assignments++;
                    }
                    rows.add(Map.of("function",f.getName(),"spec",spec,"status","PASS","c_bytes",result.getDecompiledFunction().getC().getBytes(java.nio.charset.StandardCharsets.UTF_8).length));cases++;
                }
            }finally{dec.dispose();}
            XenonEvidence.writeAtomic(out,Map.of("status","PASS","checks",checks,"functions",cases,"assignments",assignments,"result_sha256",HexFormat.of().formatHex(digest.digest()),"results",rows));println("S7_FP_COMPARE_OPTIMIZED_PASS "+cases);
        }catch(Throwable e){XenonEvidence.writeAtomic(out,Map.of("status","FAIL","checks",checks,"functions",cases,"assignments",assignments,"error",e.toString()));throw e;}
        finally{p.release(owner);}
    }
}
