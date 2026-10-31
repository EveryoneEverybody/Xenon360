package xenon360.analysis;

import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** Physical proof for bounded MSVC relative dispatches, independent of
 * decompiler completion. Called inside XenonSwitchAnalyzer's rollback transaction.
 * Includes the terminal-NOP byte schedule; the original byte matcher stays intact.
 * No function creation, symbol changes, or reference deletion is performed here. */
public final class HalfwordSwitchRecovery {
    private static final int MAX_CASES=512, MAX_EXTRA_BYTES=65536, MAX_TABLES=32;
    private record Table(Address branch,Address guard,Address data,Address base,Address fallback,
                         int count,SortedSet<Address> targets,int width,int scale) {}
    public record Result(int matched,int extended,int references,Map<String,Object> evidence) {}
    private record Edge(Address from,Address to) {}
    private record Plan(Function function,Map<Address,Table> tables,AddressSet extra,AddressSet calledCode) {}
    private HalfwordSwitchRecovery() {}

    private static long pair(int high,int low) {
        return (((long)(short)high<<16)+(short)low)&0xffffffffL;
    }

    private static Table match(Program p,Address branch,Function owner) throws Exception {
        Table halfword=matchHalfword(p,branch,owner);
        return halfword!=null?halfword:matchPaddedByte(p,branch,owner);
    }

    private static Table matchHalfword(Program p,Address branch,Function owner) throws Exception {
        var memory=p.getMemory();var text=memory.getBlock(branch);
        if(text==null||!text.contains(branch.subtract(4)))return null;
        int length=memory.getInt(branch.subtract(4))==0x60000000?12:11;
        var first=branch.subtract((length-1)*4L);
        if(text==null || !text.isExecute() || !text.isInitialized() || !text.contains(first))return null;
        int[] w=new int[length];for(int n=0;n<length;n++)w[n]=memory.getInt(first.add(n*4L));
        if((w[1]&0xffff0003)!=0x41990000 ||
            w[5]!=0x7c0c022e || (w[6]&0xffff0000)!=0x3d800000 ||
            (w[7]&0xffff0000)!=0x398c0000 || w[8]!=0x7d8c0214 ||
            w[9]!=0x7d8903a6 || w[length-1]!=0x4e800420)return null;
        int high,low,shift;
        if((w[2]&0xffff0000)==0x3d800000&&(w[3]&0xffff0000)==0x398c0000&&(w[4]&0xfc1fffff)==0x5400083c){high=2;low=3;shift=4;}
        else if((w[3]&0xffff0000)==0x3d800000&&(w[4]&0xffff0000)==0x398c0000&&(w[2]&0xfc1fffff)==0x5400083c){high=3;low=4;shift=2;}
        else return null;
        int index=(w[shift]>>>21)&31;
        // The index must be copied before any overwrite by address construction.
        if(index==12&&shift==4)return null;
        Address guard=first;int compare=w[0],gap=0;
        while((compare&0xffff0000)!=(0x2b000000|(index<<16))) {
            // Permit at most four non-updating stack stores between cmp and bgt.
            if(gap++==4 || (compare&0xfc1f0000)!=0x90010000)return null;
            guard=guard.subtract(4);if(!text.contains(guard))return null;
            compare=memory.getInt(guard);
        }
        if(index==1&&gap!=0)return null;
        int count=(compare&65535)+1;if(count<2 || count>MAX_CASES)return null;
        long baseValue=pair(w[6],w[7]);Address base=branch.getAddressSpace().getAddress(baseValue);
        if(!text.contains(base))return null;
        Address fallback=first.add(4+(short)(w[1]&0xfffc));
        if(!text.contains(fallback) || !text.contains(fallback.add(3)) ||
            (fallback.compareTo(guard)>0&&fallback.compareTo(branch)<=0))return null;
        var table=branch.getAddressSpace().getAddress(pair(w[high],w[low]));var data=memory.getBlock(table);
        if((table.getOffset()&1)!=0 || data==null || !data.isInitialized() || data.isExecute() || data.isWrite() ||
            !data.contains(table.add(count*2L-1)))return null;
        var targets=new TreeSet<Address>();
        for(int n=0;n<count;n++) {
            long value=baseValue+(memory.getShort(table.add(n*2L))&65535);
            if(value>0xffffffffL)return null;Address target=branch.getAddressSpace().getAddress(value);
            if((target.getOffset()&3)!=0 || !text.contains(target) || !text.contains(target.add(3)))return null;
            targets.add(target);
        }
        if(targets.size()<2)return null;
        for(var ref:p.getReferenceManager().getReferencesFrom(branch))
            if(ref.getReferenceType().isFlow() && (!ref.getReferenceType().isJump() || !targets.contains(ref.getToAddress())))return null;
        for(Address at=guard;at.compareTo(branch)<=0;at=at.add(4)) {
            var f=p.getFunctionManager().getFunctionContaining(at);
            if(f!=null&&!f.equals(owner))return null;
            if(p.getListing().getDefinedDataContaining(at)!=null)return null;
            var ins=p.getListing().getInstructionContaining(at);
            if(ins!=null&&(!ins.getAddress().equals(at)||ins.getFlowOverride()!=FlowOverride.NONE))return null;
            if(!at.equals(guard))for(var ref:p.getReferenceManager().getReferencesTo(at))
                if(ref.getReferenceType().isFlow()&&!ref.getFromAddress().equals(at.subtract(4)))return null;
        }
        return new Table(branch,guard,table,base,fallback,count,targets,2,1);
    }

    /** Two exact compiler schedules: scaled byte + one terminal NOP, or
     * unscaled byte + two terminal NOPs. No general register propagation. */
    private static Table matchPaddedByte(Program p,Address branch,Function owner) throws Exception {
        var memory=p.getMemory();var text=memory.getBlock(branch);Address guard=branch.subtract(44);
        if(text==null||!text.isExecute()||!text.isInitialized()||!text.contains(guard)||!text.contains(branch.add(3)))return null;
        Instruction dispatch=p.getListing().getInstructionAt(branch);
        if(dispatch==null)try{dispatch=new PseudoDisassembler(p).disassemble(branch);}catch(Exception ex){return null;}
        if(dispatch==null||!dispatch.getFlowType().isJump()||!dispatch.getFlowType().isComputed()||dispatch.getFlowOverride()!=FlowOverride.NONE)return null;
        int[] w=new int[12];for(int n=0;n<12;n++)w[n]=memory.getInt(guard.add(n*4L));
        if((w[1]&0xffff0003)!=0x41990000||(w[2]&0xffff0000)!=0x3d800000||
            (w[3]&0xffff0000)!=0x398c0000||(w[4]&0xffff07ff)!=0x7c0c00ae||w[11]!=0x4e800420)return null;
        int index=(w[4]>>>11)&31;
        // r12 is overwritten by table-address construction before the load.
        if(index==12||(w[0]&0xffff0000)!=(0x2b000000|(index<<16)))return null;
        int high,low,scale;
        if(w[5]==0x5400103a&&w[8]==0x7d8c0214&&w[9]==0x7d8903a6&&w[10]==0x60000000){high=6;low=7;scale=4;}
        else if(w[7]==0x7d8c0214&&w[8]==0x7d8903a6&&w[9]==0x60000000&&w[10]==0x60000000){high=5;low=6;scale=1;}
        else return null;
        if((w[high]&0xffff0000)!=0x3d800000||(w[low]&0xffff0000)!=0x398c0000)return null;
        int count=(w[0]&65535)+1;if(count<2||count>256)return null;
        Address table=branch.getAddressSpace().getAddress(pair(w[2],w[3]));var data=memory.getBlock(table);
        if(data==null||!data.isInitialized()||data.isWrite()||data.isExecute()||!data.contains(table.add(count-1)))return null;
        // Reading a compatible scalar byte does not replace a definition. Larger
        // data types, structures, instructions and manual/imported names are held.
        for(int n=0;n<count;n++) {
            Address at=table.add(n);var defined=p.getListing().getDefinedDataContaining(at);
            if(p.getListing().getInstructionContaining(at)!=null||
                (defined!=null&&(!(defined.getDataType() instanceof ByteDataType)||defined.getLength()!=1))||protectedSymbol(p,at))return null;
        }
        Address base=branch.getAddressSpace().getAddress(pair(w[high],w[low]));
        Address fallback=guard.add(4L+(short)(w[1]&0xfffc));
        if(!text.contains(base)||!text.contains(fallback)||!text.contains(fallback.add(3))||
            (fallback.compareTo(guard)>0&&fallback.compareTo(branch)<=0))return null;
        var targets=new TreeSet<Address>();
        for(int n=0;n<count;n++) {
            long value=base.getOffset()+(memory.getByte(table.add(n))&255)*(long)scale;
            if(value>0xffffffffL)return null;Address target=branch.getAddressSpace().getAddress(value);
            if((value&3)!=0||!text.contains(target)||!text.contains(target.add(3))||protectedSymbol(p,target))return null;
            targets.add(target);
        }
        if(targets.size()<2)return null;
        for(var ref:p.getReferenceManager().getReferencesFrom(branch))
            if(ref.getReferenceType().isFlow()&&(!ref.getReferenceType().isJump()||!targets.contains(ref.getToAddress())))return null;
        for(Address at=guard;at.compareTo(branch)<=0;at=at.add(4)) {
            var f=p.getFunctionManager().getFunctionContaining(at);var ins=p.getListing().getInstructionContaining(at);
            if((f!=null&&!f.equals(owner))||p.getListing().getDefinedDataContaining(at)!=null||
                (ins!=null&&(!ins.getAddress().equals(at)||ins.getFlowOverride()!=FlowOverride.NONE))||protectedSymbol(p,at))return null;
            if(!at.equals(guard))for(var ref:p.getReferenceManager().getReferencesTo(at))
                if(ref.getReferenceType().isFlow()&&!ref.getFromAddress().equals(at.subtract(4)))return null;
        }
        return new Table(branch,guard,table,base,fallback,count,targets,1,scale);
    }

    private static boolean protectedSymbol(Program p,Address at) {
        return Arrays.stream(p.getSymbolTable().getSymbols(at)).anyMatch(s->s.getSource()==SourceType.USER_DEFINED||s.getSource()==SourceType.IMPORTED);
    }

    private static Plan preflight(Program p,Function f,Table root,TaskMonitor monitor) throws Exception {
        var old=f.getBody();var extra=new AddressSet();var tables=new TreeMap<Address,Table>();tables.put(root.branch(),root);
        var edges=new ArrayList<Edge>();var calls=new TreeSet<Address>();var queue=new ArrayDeque<Address>(root.targets());queue.add(root.fallback());
        var decoder=new PseudoDisassembler(p);var text=p.getMemory().getBlock(root.branch());
        // Retain the byte family's 4 KiB budget; halfword limits are unchanged.
        int maxExtra=root.width()==1?4096:MAX_EXTRA_BYTES;
        Address end=root.branch().add(maxExtra+3L);
        while(!queue.isEmpty()) {
            monitor.checkCancelled();Address at=queue.removeFirst();
            if(old.contains(at)){if(p.getListing().getInstructionAt(at)==null)return null;continue;}
            if(extra.contains(at))continue;
            if(extra.getNumAddresses()>=maxExtra || at.compareTo(f.getEntryPoint())<0 ||
                at.compareTo(end)>0 || !text.contains(at) || !text.contains(at.add(3)) || (at.getOffset()&3)!=0)return null;
            if(p.getFunctionManager().getFunctionContaining(at)!=null || p.getListing().getDefinedDataContaining(at)!=null ||
                p.getListing().getDefinedData(new AddressSet(at,at.add(3)),true).hasNext())return null;
            if(Arrays.stream(p.getSymbolTable().getSymbols(at)).anyMatch(s->s.getSource()==SourceType.USER_DEFINED||s.getSource()==SourceType.IMPORTED))return null;
            Instruction instruction=p.getListing().getInstructionContaining(at);
            if(instruction!=null&&!instruction.getAddress().equals(at))return null;
            if(root.width()==1&&instruction!=null&&instruction.getFlowOverride()!=FlowOverride.NONE)return null;
            if(instruction==null)try{instruction=decoder.disassemble(at);}catch(Exception ex){return null;}
            if(instruction==null||instruction.getLength()!=4)return null;
            extra.add(at,at.add(3));var flow=instruction.getFlowType();
            if(flow.isJump()&&flow.isComputed()) {
                // Preserve the halfword family's prior acceptance boundary.
                Table nested=root.width()==1?match(p,at,f):matchHalfword(p,at,f);
                if(nested==null || tables.size()>=MAX_TABLES)return null;
                tables.put(at,nested);queue.add(nested.fallback());
                for(Address to:nested.targets()){edges.add(new Edge(at,to));queue.add(to);}
            }else if(flow.isJump())for(Address to:instruction.getFlows()) {
                if(!flow.isConditional()&&p.getFunctionManager().getFunctionAt(to)!=null&&!old.contains(to))continue;
                edges.add(new Edge(at,to));queue.add(to);
            }
            Address next=instruction.getFallThrough();
            if(flow.isCall())for(Address to:instruction.getFlows()) {
                var target=p.getFunctionManager().getFunctionAt(to);if(target!=null&&target.hasNoReturn())next=null;
                if(!flow.isComputed())calls.add(to);
            }
            if(next!=null)queue.add(next);
        }
        var body=new AddressSet(old);body.add(extra);
        for(Table t:tables.values()) {
            if(!body.contains(t.guard(),t.branch()))return null;
            for(Table origin:tables.values())for(Address target:origin.targets())
                if(target.compareTo(t.guard())>0&&target.compareTo(t.branch())<=0)return null;
            for(Edge edge:edges)if(edge.to().compareTo(t.guard())>0&&edge.to().compareTo(t.branch())<=0&&
                !edge.from().equals(edge.to().subtract(4)))return null;
        }
        AddressSet calledCode=root.width()==1?new AddressSet():preflightCalls(p,body,calls,monitor);
        if(calledCode==null)return null;
        return new Plan(f,tables,extra,calledCode);
    }

    /** Follow only proven direct calls into currently undefined executable code.
     * Keep these instructions outside the caller body; normal Ghidra analysis owns
     * function creation. The extra call graph is limited to 16 entries / 4 KiB. */
    private static AddressSet preflightCalls(Program p,AddressSetView caller,SortedSet<Address> targets,TaskMonitor monitor) throws Exception {
        var result=new AddressSet();var pending=new ArrayDeque<Address>(targets);var entries=new HashSet<Address>();var decoder=new PseudoDisassembler(p);
        while(!pending.isEmpty()) {
            monitor.checkCancelled();Address entry=pending.removeFirst();
            if(caller.contains(entry)||p.getListing().getInstructionAt(entry)!=null||!entries.add(entry))continue;
            var block=p.getMemory().getBlock(entry);
            if(block==null||!block.isExecute())continue; // external/unmapped calls are not speculative entry points
            if(entries.size()>16)return null;
            var queue=new ArrayDeque<Address>();queue.add(entry);
            while(!queue.isEmpty()) {
                monitor.checkCancelled();Address at=queue.removeFirst();
                if(result.contains(at)||caller.contains(at)||p.getListing().getInstructionAt(at)!=null)continue;
                if(result.getNumAddresses()>=4096 || at.compareTo(entry)<0 || at.subtract(entry)>=4096 ||
                    (at.getOffset()&3)!=0 || !block.contains(at) || !block.contains(at.add(3)))return null;
                if(p.getFunctionManager().getFunctionContaining(at)!=null || p.getListing().getInstructionContaining(at)!=null ||
                    p.getListing().getDefinedDataContaining(at)!=null || p.getListing().getDefinedData(new AddressSet(at,at.add(3)),true).hasNext())return null;
                if(Arrays.stream(p.getSymbolTable().getSymbols(at)).anyMatch(s->s.getSource()==SourceType.USER_DEFINED||s.getSource()==SourceType.IMPORTED))return null;
                Instruction i;try{i=decoder.disassemble(at);}catch(Exception ex){return null;}
                if(i==null||i.getLength()!=4)return null;result.add(at,at.add(3));var flow=i.getFlowType();
                if(flow.isJump()&&flow.isComputed())return null;
                if(flow.isJump())for(Address to:i.getFlows()) {
                    if(p.getFunctionManager().getFunctionAt(to)!=null)continue;
                    queue.add(to);
                }
                Address next=i.getFallThrough();
                if(flow.isCall())for(Address to:i.getFlows()) {
                    if(!flow.isComputed())pending.add(to);
                    var f=p.getFunctionManager().getFunctionAt(to);if(f!=null&&f.hasNoReturn())next=null;
                }
                if(next!=null)queue.add(next);
            }
        }
        return result;
    }

    /** Null means the pattern is not supported. A withheld result never mutates. */
    public static Result recover(Program p,Address branch,TaskMonitor monitor) throws Exception {
        var f=p.getFunctionManager().getFunctionContaining(branch);
        if(f==null||f.getSymbol().getSource()!=SourceType.DEFAULT)return null;
        Table table=match(p,branch,f);if(table==null||!f.getBody().contains(table.guard(),branch))return null;
        if(table.width()==1)for(Address at=table.guard();at.compareTo(branch)<=0;at=at.add(4))
            if(p.getListing().getInstructionAt(at)==null)return null;
        Plan plan=preflight(p,f,table,monitor);
        var evidence=new LinkedHashMap<String,Object>();evidence.put("binary_sha256",XenonEvidence.sourceHash(p));
        evidence.put("branch",branch.toString());evidence.put("function_address",f.getEntryPoint().toString());
        evidence.put("table_address",table.data().toString());evidence.put("entry_count",table.count());
        evidence.put("relative_base",table.base().toString());
        evidence.put("entry_width",table.width());evidence.put("offset_scale",table.scale());evidence.put("targets",table.targets().stream().map(Object::toString).toList());
        evidence.put("identification_source",table.width()==1?
            "physical unsigned cmplwi/bgt, read-only lbzx bytes, explicit constant base, exact CTR dataflow, terminal NOP schedule":
            "physical unsigned cmplwi/bgt, r0 index*2, read-only lhzx halfwords, explicit constant base, exact CTR dataflow");
        evidence.put("status",plan==null?"withheld_ownership_or_data":"validated_present");
        if(plan==null)return new Result(1,0,0,evidence);
        int refs=0;var body=new AddressSet(f.getBody());body.add(plan.extra());
        var disassembly=new AddressSet(plan.extra());disassembly.add(plan.calledCode());
        var allowed=new AddressSet(body);allowed.add(plan.calledCode());
        // All bounds, instructions, owners and nested dispatches are proved before the first mutation.
        var starts=new AddressSet();
        for(var range:disassembly.getAddressRanges())for(Address at=range.getMinAddress();at.compareTo(range.getMaxAddress())<=0;at=at.add(4)) {
            monitor.checkCancelled();if(p.getListing().getInstructionAt(at)==null)starts.add(at);
        }
        if(!starts.isEmpty()) {
            var command=new DisassembleCommand(starts,allowed,false);command.enableCodeAnalysis(false);
            if(!command.applyTo(p,monitor)){monitor.checkCancelled();throw new IllegalStateException("Bounded halfword disassembly failed: "+command.getStatusMsg());}
        }
        for(var range:disassembly.getAddressRanges())for(Address at=range.getMinAddress();at.compareTo(range.getMaxAddress())<=0;at=at.add(4)) {
            monitor.checkCancelled();var instruction=p.getListing().getInstructionAt(at);
            if(instruction==null||instruction.getLength()!=4)throw new IllegalStateException("Missing preflighted halfword-switch instruction at "+at);
        }
        for(Table t:plan.tables().values())for(Address target:t.targets()) {
            monitor.checkCancelled();boolean present=false;
            for(var ref:p.getReferenceManager().getReferencesFrom(t.branch()))
                if(ref.getReferenceType().isJump()&&ref.getToAddress().equals(target)){present=true;break;}
            if(!present){p.getReferenceManager().addMemoryReference(t.branch(),target,RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);refs++;}
        }
        if(!plan.extra().isEmpty())f.setBody(body);
        monitor.checkCancelled();
        // Newly reached code can change constant propagation throughout the owner, not only in the added ranges.
        if(refs!=0||!plan.extra().isEmpty())AutoAnalysisManager.getAnalysisManager(p).codeDefined(allowed);
        evidence.put("validated_dispatches",plan.tables().keySet().stream().map(Object::toString).toList());
        evidence.put("new_body_bytes",plan.extra().getNumAddresses());
        evidence.put("direct_call_code_bytes",plan.calledCode().getNumAddresses());
        return new Result(plan.tables().size(),plan.extra().isEmpty()?0:1,refs,evidence);
    }
}
