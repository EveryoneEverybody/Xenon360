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
 * and every output byte must match the architectural byte mapping. */
public class XenonVmxPermuteStructuredTest extends GhidraScript {
    private int checks,cases,assignments;
    private void check(boolean ok,String s){checks++;if(!ok)throw new AssertionError(s);}
    private int memory(int operation,int v,int r){return 4<<26|(v&31)<<21|r<<11|operation<<6|(v>>>5)<<2|3;}
    private int splat(boolean immediate,int d,int source,int field){return (immediate?0x18000770:0x18000730)|(d&31)<<21|field<<16|(source&31)<<11|(d>>>5)<<2|(source>>>5);}
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
    private byte[] aBytes,bBytes,cBytes;
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
                for(int r=3;r<=6;r++){
                    var reg=p.getRegister("r"+r);long delta=v.getOffset()-reg.getAddress().getOffset();
                    if(v.getAddress().getAddressSpace().equals(reg.getAddress().getAddressSpace())&&delta>=0&&delta+v.getSize()<=reg.getMinimumByteSize()){
                        long address=r==3?0x1000:r==4?0x2000+offset:r==5?0x3000+offset:0x4000+offset;
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
                    case PcodeOp.INT_SUB -> value(x[0]).subtract(value(x[1]));
                    case PcodeOp.INT_NEGATE -> value(x[0]).not();
                    case PcodeOp.INT_2COMP -> value(x[0]).negate();
                    case PcodeOp.INT_MULT -> value(x[0]).multiply(value(x[1]));
                    case PcodeOp.PTRADD -> value(x[0]).add(value(x[1]).multiply(value(x[2])));
                    case PcodeOp.LOAD -> {
                        long address=value(x[1]).longValueExact();byte[] bytes=new byte[v.getSize()];
                        for(int i=0;i<bytes.length;i++){
                            long at=address+i;byte[] src=at>=0x2000&&at<0x2010?aBytes:at>=0x3000&&at<0x3010?bBytes:at>=0x4000&&at<0x4010?cBytes:null;
                            if(src==null){
                                if(at>=0x84000000L&&at<0x84002000L){try{bytes[i]=p.getMemory().getByte(p.getAddressFactory().getDefaultAddressSpace().getAddress(at));}catch(Exception e){throw new AssertionError(e);}continue;}
                                throw new AssertionError("unexpected high LOAD address "+Long.toHexString(at));
                            }
                            bytes[i]=src[(int)(at&15)];
                        }yield new BigInteger(1,bytes);
                    }
                    default -> throw new AssertionError("unsupported high operation in store dependency: "+op);
                };
            }
            result=result.and(mask(v.getSize()));active.remove(v);memo.put(v,result);return result;
        }
    }
    private byte[] loaded(byte[] input,int offset){byte[] r=new byte[16];System.arraycopy(input,offset,r,0,16-offset);return r;}
    private byte[] structured(int kind){
        if(kind<9)return XenonVmxPermuteOracle.control(kind);
        byte[] mask=new byte[16];
        for(int i=0;i<16;i++)mask[i]=(byte)(kind<13?(i+new int[]{1,3,7,15}[kind-9])&31:kind==13?i|0xe0:(i%2==0?i/2:16+i/2)|0xe0);
        return mask;
    }
    @Override protected void run()throws Exception{
        Path output=Path.of(getScriptArgs()[0]);List<Object> rows=new ArrayList<>();
        var language=getLanguage(new LanguageID("PowerPC:BE:64:Xenon-VMX128-32addr"));Object owner=new Object();
        ProgramDB p=new ProgramDB("native-permute-decompiler-regression",language,language.getDefaultCompilerSpec(),owner);
        Map<String,int[]> specs=new LinkedHashMap<>();MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try{
            var start=p.getAddressFactory().getDefaultAddressSpace().getAddress(0x83000000L);int tx=p.startTransaction("synthetic dynamic-control functions");
            try{
                p.getMemory().createInitializedBlock("code",start,0x20000,(byte)0,TaskMonitor.DUMMY,false).setExecute(true);int index=0;
                List<int[]> tuples=new ArrayList<>();
                tuples.add(new int[]{127,32,64,0});
                for(int r=0;r<128;r++)tuples.add(new int[]{(r+37)%128,r,r,r%8});
                for(int k=0;k<15;k++)tuples.add(new int[]{127,32,64,0,9+k});
                var masks=p.getMemory().createInitializedBlock("constant_masks",start.getAddressSpace().getAddress(0x84000000L),0x2000,(byte)0,TaskMonitor.DUMMY,false);
                for(int partial:new int[]{0,1})for(int[] tuple:tuples){
                    int d=tuple[0],a=tuple[1],b=tuple[2],c=tuple[3],op=partial==0?3:16;
                    int mode=tuple.length>4?tuple[4]:0;
                    String name="permute_"+partial+"_"+d+"_"+a+"_"+b+"_"+c+"_"+index+"_mode"+mode;
                    var entry=start.add(index++*0x100);
                    List<Integer> words=new ArrayList<>(List.of(memory(op,a,4),memory(op,b,5),memory(op,c,6)));
                    if(mode==1||mode==4)words.add(splat(false,a,a,1));
                    if(mode>=5&&mode<=8)words.add(splat(true,c,0,new int[]{0,15,16,31}[mode-5]));
                    if(mode>=9){
                        int off=(index-1)*16;
                        p.getMemory().setBytes(start.getAddressSpace().getAddress(0x84000000L+off),structured(mode-9));
                        words.add(0,0x60c60000|off); // ori r6,r6,offset
                        words.add(0,0x3cc08400); // lis r6,0x8400
                    }
                    words.add(XenonVmxPermuteOracle.encoding(d,a,b,c));
                    if(mode>=2&&mode<=4)words.add(merge(mode==3,d,d,b));
                    words.add(memory(7,d,3));words.add(0x4e800020);
                    ByteBuffer buffer=ByteBuffer.allocate(words.size()*4).order(ByteOrder.BIG_ENDIAN);for(int w:words)buffer.putInt(w);byte[] code=buffer.array();
                    p.getMemory().setBytes(entry,code);
                    check(new DisassembleCommand(entry,new AddressSet(entry,entry.add(code.length-1)),true).applyTo(p,TaskMonitor.DUMMY),"fixture disassembly "+name);
                    p.getFunctionManager().createFunction(name,entry,new AddressSet(entry,entry.add(code.length-1)),SourceType.USER_DEFINED);
                    specs.put(name,new int[]{partial,d,a,b,c,mode});
                }
                masks.setWrite(false);
            }finally{p.endTransaction(tx,true);}
            DecompInterface decompiler=new DecompInterface();
            // This fixture explicitly presents known constants. Dynamic tests remain unchanged.
            var options=new ghidra.app.decompiler.DecompileOptions();
            options.setRespectReadOnly(true);decompiler.setOptions(options);
            try{
                check(decompiler.openProgram(p),"opens fixture");var functions=p.getFunctionManager().getFunctions(true);
                while(functions.hasNext()){
                    Function f=functions.next();int[] spec=specs.get(f.getName());long began=System.nanoTime();
                    var result=decompiler.decompileFunction(f,20,monitor);
                    check(result.decompileCompleted()&&result.getHighFunction()!=null,"completed "+f.getName()+": "+result.getErrorMessage());
                    List<PcodeOp> stores=new ArrayList<>();List<String> high=new ArrayList<>(),raw=new ArrayList<>(),unsupported=new ArrayList<>();boolean[] dep=new boolean[3];int opaque=0,loads=0;
                    var ops=result.getHighFunction().getPcodeOps();while(ops.hasNext()){
                        PcodeOp op=ops.next();high.add(op.toString());
                        if(op.getOpcode()==PcodeOp.LOAD){
                            loads++;long at=op.getSeqnum().getTarget().getOffset()-f.getEntryPoint().getOffset()-(spec[5]>=9?8:0);
                            if(at>=0&&at<=8&&at%4==0)dep[(int)at/4]|=reachesStore(op.getOutput());
                        }
                        if(op.getOpcode()==PcodeOp.STORE)stores.add(op);if(op.getOpcode()==PcodeOp.CALLOTHER)opaque++;
                        // This is deliberately a straight-line evaluator. Never pick a PHI input.
                        if(!Set.of(PcodeOp.COPY,PcodeOp.CAST,PcodeOp.LOAD,PcodeOp.STORE,PcodeOp.RETURN,
                            PcodeOp.SUBPIECE,PcodeOp.PIECE,PcodeOp.INT_ZEXT,PcodeOp.INT_SEXT,
                            PcodeOp.INT_LEFT,PcodeOp.INT_RIGHT,PcodeOp.INT_OR,PcodeOp.INT_AND,PcodeOp.INT_XOR,
                            PcodeOp.INT_ADD,PcodeOp.INT_SUB,PcodeOp.INT_MULT,PcodeOp.INT_NEGATE,PcodeOp.INT_2COMP,
                            PcodeOp.PTRADD,PcodeOp.PTRSUB).contains(op.getOpcode()))unsupported.add(op.toString());
                    }
                    var instructions=p.getListing().getInstructions(f.getBody(),true);while(instructions.hasNext()){
                        var ins=instructions.next();raw.add(ins.getAddress()+" "+ins+" bytes="+HexFormat.of().formatHex(ins.getBytes()));for(PcodeOp op:ins.getPcode())raw.add(op.toString());
                    }
                    Map<String,Object> row=new LinkedHashMap<>();rows.add(row);row.put("function",f.getName());row.put("spec",spec);
                    row.put("load_dependencies",dep);row.put("loads",loads);row.put("stores",stores.size());row.put("opaque",opaque);
                    row.put("c",result.getDecompiledFunction().getC());row.put("raw_pcode",raw);row.put("high_pcode",high);row.put("elapsed_seconds",(System.nanoTime()-began)/1e9);row.put("warning",result.getErrorMessage());
                    check(unsupported.isEmpty(),"unsupported high operation/control flow: "+unsupported);
                    boolean[] needed=spec[5]>=5&&spec[5]<=8?new boolean[]{spec[5]<=6,spec[5]>=7,false}:new boolean[]{spec[2]!=spec[3]&&spec[2]!=spec[4],spec[3]!=spec[4],true};if(spec[5]>=9){needed=new boolean[]{false,false,false};for(byte v:structured(spec[5]-9))needed[(v&31)<16?0:1]=true;}
                    row.put("required_dependencies",needed);
                    // An unselected constant-mask source may remain syntactically
                    // connected through a provably zero shift. Require the selected
                    // source and reject a stale control LOAD, without demanding that
                    // the optimizer perform optional constant folding. Exact values
                    // below still prove the unselected source has no effect.
                    boolean dependencies=spec[5]>=5&&spec[5]<=8?(!dep[2]&&(!needed[0]||dep[0])&&(!needed[1]||dep[1])):Arrays.equals(dep,needed);
                    if(spec[5]>=9)dependencies=(!needed[0]||dep[0])&&(!needed[1]||dep[1]);
                    check(dependencies,"expected A/B/C LOAD dependency "+f.getName());check(opaque==0,"native high-p-code "+f.getName());
                    List<Object> values=new ArrayList<>();row.put("values",values);
                    // All 256 selector values at every byte in the first distinct-input function.
                    // Every other function uses sixteen independently assigned A/B/C triples.
                    int variants=cases==0?272:16;
                    for(int assignment=0;assignment<variants;assignment++)for(int offset:spec[0]==0?new int[]{0}:new int[]{0,1,3}){
                        aBytes=XenonVmxPermuteOracle.pattern(assignment%6,0);bBytes=XenonVmxPermuteOracle.pattern(assignment%6,1);
                        cBytes=XenonVmxPermuteOracle.control(assignment%9);
                        if(assignment>=16)for(int i=0;i<16;i++)cBytes[i]=(byte)(assignment-16+i*17);
                        else if(assignment>=12){Random rng=new Random(0x5065726dL+assignment);rng.nextBytes(aBytes);rng.nextBytes(bBytes);rng.nextBytes(cBytes);}
                        Evaluator evaluator=new Evaluator(p,offset);byte[] stored=new byte[16];boolean[] covered=new boolean[16];List<Long> addresses=new ArrayList<>();
                        for(PcodeOp store:stores){
                            long address=evaluator.value(store.getInput(1)).longValueExact();addresses.add(address);Varnode v=store.getInput(2);BigInteger n=evaluator.value(v);
                            for(int i=0;i<v.getSize();i++){
                                int dst=Math.toIntExact(address-0x1000+i);check(dst>=0&&dst<16&&!covered[dst],"exact output write coverage");covered[dst]=true;stored[dst]=n.shiftRight((v.getSize()-i-1)*8).byteValue();
                            }
                        }
                        byte[][] effective=XenonVmxPermuteOracle.effective(spec[2],spec[3],spec[4],loaded(aBytes,offset),loaded(bBytes,offset),loaded(cBytes,offset));
                        int mode=spec[5];
                        if(mode==1||mode==4){byte[] word=Arrays.copyOfRange(effective[0],4,8),splat=new byte[16];for(int i=0;i<4;i++)System.arraycopy(word,0,splat,i*4,4);effective[0]=splat;}
                        if(mode>=5&&mode<=8){byte[] word=XenonVmxPermuteOracle.word(new int[]{0,15,-16,-1}[mode-5]),constant=new byte[16];for(int i=0;i<4;i++)System.arraycopy(word,0,constant,i*4,4);effective[2]=constant;}
                        if(mode>=9)effective[2]=structured(mode-9);
                        byte[] expected=XenonVmxPermuteOracle.permute(effective[0],effective[1],effective[2]);
                        if(mode>=2&&mode<=4){byte[] permuted=expected;expected=new byte[16];int first=mode==3?8:0;for(int i=0;i<2;i++){System.arraycopy(permuted,first+i*4,expected,i*8,4);System.arraycopy(effective[1],first+i*4,expected,i*8+4,4);}}
                        for(boolean c:covered)check(c,"all stored bytes covered");
                        Map<String,Object> value=new LinkedHashMap<>();value.put("assignment",assignment);value.put("offset",offset);value.put("addresses",addresses);
                        value.put("a",HexFormat.of().formatHex(effective[0]));value.put("b",HexFormat.of().formatHex(effective[1]));value.put("c",HexFormat.of().formatHex(effective[2]));value.put("expected",HexFormat.of().formatHex(expected));value.put("actual",HexFormat.of().formatHex(stored));values.add(value);
                        check(Arrays.equals(stored,expected),"architectural high-p-code byte permutation "+f.getName()+" assignment="+assignment+" offset="+offset);
                        digest.update(stored);assignments++;
                    }
                    row.put("status","PASS");cases++;
                }
            }finally{decompiler.dispose();}
            check(cases==288,"all additional identity and structured-control fixtures");
            XenonEvidence.writeAtomic(output,Map.of("schema","xenon360/native-permute-structured-v1","status","PASS","checks",checks,"decompiler_cases",cases,"assignments",assignments,"result_sha256",HexFormat.of().formatHex(digest.digest()),"results",rows));
            println("XENON_VMX_PERMUTE_STRUCTURED_PASS checks="+checks+" cases="+cases+" assignments="+assignments);
        }catch(Throwable failure){XenonEvidence.writeAtomic(output,Map.of("status","FAIL","checks",checks,"completed_cases",cases,"assignments",assignments,"error",failure.toString(),"results",rows));throw failure;}
        finally{p.release(owner);}
    }
}
