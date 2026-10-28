package xenon360;

import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.services.*;
import ghidra.app.util.PseudoDisassembler;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/** Recover bounded MSVC byte-index and unsigned-halfword switches without trusting decompiler constants.
 * The unsigned guard, table address, scale and branch base are all physical instructions.
 */
public final class XenonSwitchAnalyzer extends AbstractAnalyzer {
    public static final String NAME="Xenon360 Bounded Switch Tables";
    private record Table(Address branch,Function function,SortedSet<Address> targets,Address data,int count,int scale) {}
    public XenonSwitchAnalyzer() {
        super(NAME,"Recover physically bounded Xenon byte and halfword switch tables while preserving owners and symbols.",AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);setSupportsOneTimeAnalysis();
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after());
    }
    @Override public boolean canAnalyze(Program p) {
        return p.getLanguageID().toString().equals("PowerPC:BE:64:Xenon-VMX128-32addr");
    }
    private Table match(Program p,Instruction branch) throws Exception {
        if(branch.getFlowOverride()!=FlowOverride.NONE || p.getMemory().getInt(branch.getAddress())!=0x4e800420)return null;
        var at=branch.getAddress();var start=at.subtract(44);var block=p.getMemory().getBlock(at);
        Function f=p.getFunctionManager().getFunctionContaining(at);
        if(f==null || f.getSymbol().getSource()!=SourceType.DEFAULT || !f.getBody().contains(start,at) ||
            block==null || !block.contains(start))return null;
        int[] w=new int[12];for(int i=0;i<w.length;i++)w[i]=p.getMemory().getInt(start.add(i*4L));
        if((w[0]&0xffff0000)!=0x2b0b0000 || (w[0]&0xffff)>255 ||
            (w[1]&0xffff0003)!=0x41990000 || (w[2]&0xffff0000)!=0x3d800000 ||
            (w[3]&0xffff0000)!=0x398c0000 || w[4]!=0x7c0c58ae ||
            w[9]!=0x7d8c0214 || w[10]!=0x7d8903a6)return null;
        int hi,lo,scale;
        if(w[5]==0x5400103a && w[7]==0x60000000){hi=6;lo=8;scale=2;}
        else if(w[6]==0x60000000 && w[8]==0x60000000){hi=5;lo=7;scale=0;}
        else return null;
        if((w[hi]&0xffff0000)!=0x3d800000 || (w[lo]&0xffff0000)!=0x398c0000)return null;
        long base=(((long)(short)w[hi]<<16)+(short)w[lo])&0xffffffffL;
        if(base!=at.add(4).getOffset())return null;
        Address defaultTarget=start.add(4L+(short)(w[1]&0xfffc));
        if(!f.getBody().contains(defaultTarget))return null;
        long tableValue=(((long)(short)w[2]<<16)+(short)w[3])&0xffffffffL;
        Address table=p.getAddressFactory().getDefaultAddressSpace().getAddress(tableValue);
        int count=(w[0]&0xffff)+1;var data=p.getMemory().getBlock(table);
        if(data==null || !data.isInitialized() || data.isExecute() || data.isWrite() || !data.contains(table.add(count-1)))return null;
        var targets=new TreeSet<Address>();
        for(int i=0;i<count;i++) {
            var target=at.add(4L+((p.getMemory().getByte(table.add(i))&255)<<scale));
            if((target.getOffset()&3)!=0 || !block.contains(target) || !block.contains(target.add(3)))return null;
            targets.add(target);
        }
        if(targets.size()<2)return null;
        for(var ref:branch.getReferencesFrom())if(ref.getReferenceType().isFlow() && !targets.contains(ref.getToAddress()))return null;
        return new Table(at,f,targets,table,count,scale);
    }
    private AddressSet preflight(Program p,Table table,TaskMonitor monitor) throws Exception {
        var old=table.function().getBody();var extra=new AddressSet();
        var queue=new ArrayDeque<Address>(table.targets());var decoder=new PseudoDisassembler(p);
        var block=p.getMemory().getBlock(table.branch());
        while(!queue.isEmpty()) {
            monitor.checkCancelled();var at=queue.removeFirst();
            if(old.contains(at)) {if(p.getListing().getInstructionAt(at)==null)return null;continue;}
            if(extra.contains(at))continue;
            if(extra.getNumAddresses()>=4096 || at.compareTo(table.function().getEntryPoint())<0 ||
                at.subtract(table.branch())>4096 || !block.contains(at) || !block.contains(at.add(3)) || (at.getOffset()&3)!=0)return null;
            if(p.getFunctionManager().getFunctionContaining(at)!=null ||
                p.getListing().getDefinedDataContaining(at)!=null ||
                p.getListing().getDefinedData(new AddressSet(at,at.add(3)),true).hasNext())return null;
            if(Arrays.stream(p.getSymbolTable().getSymbols(at)).anyMatch(s->s.getSource()==SourceType.USER_DEFINED || s.getSource()==SourceType.IMPORTED))return null;
            Instruction i=p.getListing().getInstructionContaining(at);
            if(i!=null && !i.getAddress().equals(at))return null;
            if(i==null)try{i=decoder.disassemble(at);}catch(Exception ex){return null;}
            if(i==null || i.getLength()!=4)return null;
            extra.add(at,at.add(3));var flow=i.getFlowType();
            if(flow.isJump() && !flow.isComputed())for(var to:i.getFlows()) {
                if(!flow.isConditional() && p.getFunctionManager().getFunctionAt(to)!=null && !old.contains(to))continue;
                queue.add(to);
            }
            // An additional unresolved computed branch is outside this exact proof.
            if(flow.isJump() && flow.isComputed())return null;
            if(i.getFallThrough()!=null)queue.add(i.getFallThrough());
        }
        return extra;
    }
    @Override public boolean added(Program p,AddressSetView set,TaskMonitor monitor,MessageLog log) throws CancelledException {
        if(!set.contains(p.getMemory()))return false;
        int tx=p.startTransaction(NAME);boolean commit=false;int matched=0,extended=0,refs=0,withheld=0;
        var evidence=new ArrayList<Map<String,Object>>();var recoveredHalfwords=new HashSet<String>();
        try {
            var branches=new ArrayList<Address>();var it=p.getListing().getInstructions(true);long inspected=0;
            while(it.hasNext()) {
                if((inspected++&4095)==0){monitor.checkCancelled();monitor.setMessage("Xenon360: checking bounded switch tables");}
                var i=it.next();if(i.getMnemonicString().equals("bctr"))branches.add(i.getAddress());
            }
            for(var at:branches) {
                monitor.checkCancelled();var instruction=p.getListing().getInstructionAt(at);
                Table table=match(p,instruction);
                if(table==null) {
                    if(recoveredHalfwords.contains(at.toString()))continue;
                    if(matched>=512){withheld++;break;}
                    var halfword=xenon360.analysis.HalfwordSwitchRecovery.recover(p,at,monitor);
                    if(halfword!=null){
                        matched+=halfword.matched();extended+=halfword.extended();refs+=halfword.references();evidence.add(halfword.evidence());
                        if(halfword.evidence().get("status").equals("withheld_ownership_or_data"))withheld++;
                        else if(halfword.evidence().get("validated_dispatches") instanceof List<?> dispatches)for(var dispatch:dispatches)recoveredHalfwords.add(dispatch.toString());
                    }
                    continue;
                }
                if(++matched>512){withheld++;break;}
                AddressSet extra=preflight(p,table,monitor);
                evidence.add(Map.of("binary_sha256",xenon360.analysis.XenonEvidence.sourceHash(p),
                    "branch",at.toString(),"function_address",table.function().getEntryPoint().toString(),
                    "table_address",table.data().toString(),"entry_count",table.count(),"offset_scale",1<<table.scale(),
                    "targets",table.targets().stream().map(Object::toString).toList(),
                    "identification_source","exact unsigned cmplwi/bgt guard, read-only byte table, relative bctr",
                    "status",extra==null?"withheld_ownership_or_data":"validated_present"));
                if(extra==null){withheld++;continue;}
                var body=new AddressSet(table.function().getBody());body.add(extra);
                for(var target:table.targets())if(p.getListing().getInstructionAt(target)==null) {
                    var command=new DisassembleCommand(target,body,true);command.enableCodeAnalysis(false);
                    if(!command.applyTo(p,monitor)){monitor.checkCancelled();throw new IllegalStateException("Switch disassembly failed at "+target+": "+command.getStatusMsg());}
                }
                if(!extra.isEmpty()){table.function().setBody(body);extended++;}
                for(var target:table.targets()) {
                    boolean present=false;
                    for(var ref:instruction.getReferencesFrom())if(ref.getReferenceType().isJump() && ref.getToAddress().equals(target)){present=true;break;}
                    if(!present){p.getReferenceManager().addMemoryReference(at,target,RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);refs++;}
                }
            }
            String summary="matched="+matched+";extended="+extended+";new_references="+refs+";withheld="+withheld;
            monitor.checkCancelled();
            p.getOptions("Xenon360").setString("Switch analysis summary",summary);
            p.getOptions("Xenon360").setBoolean("Switch scan limited",matched>512);
            p.getOptions("Xenon360").setString("Switch evidence JSON",xenon360.analysis.XenonEvidence.JSON.toJson(evidence));
            Msg.info(this,summary);commit=true;return true;
        }catch(CancelledException ex){throw ex;}
        catch(Exception ex){log.appendMsg(NAME,ex.toString());log.appendException(ex);return false;}
        finally{p.endTransaction(tx,commit);}
    }
}
