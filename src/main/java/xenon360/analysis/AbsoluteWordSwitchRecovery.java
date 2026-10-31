package xenon360.analysis;

import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.util.task.TaskMonitor;

/** Exact guarded uint32 dispatch with an inline, unreachable table in read-only
 * executable storage. Runs inside XenonSwitchAnalyzer's rollback transaction.
 * This family claims at most 4 KiB of caller code, no callees and no new nested
 * dispatches. Existing byte/halfword contracts are independent and unchanged. */
public final class AbsoluteWordSwitchRecovery {
    private static final int MAX_CASES=512, MAX_EXTRA_BYTES=4096;
    private record Table(Address branch,Address guard,Address data,Address end,Address fallback,
                         int count,int index,SortedSet<Address> targets) {}
    private record Plan(AddressSet extra) {}
    private static final class Rejected extends Exception {
        Rejected(String reason){super(reason);}
    }
    private AbsoluteWordSwitchRecovery() {}
    private static void require(boolean condition,String reason)throws Rejected {
        if(!condition)throw new Rejected(reason);
    }
    private static boolean protectedSymbol(Program p,Address at) {
        return Arrays.stream(p.getSymbolTable().getSymbols(at)).anyMatch(s->s.getSource()==SourceType.USER_DEFINED||s.getSource()==SourceType.IMPORTED);
    }
    private static boolean interior(Table t,Address at) {
        return at.compareTo(t.guard())>0&&at.compareTo(t.branch())<=0;
    }
    private static boolean storage(Table t,Address at) {
        return at.compareTo(t.data())>=0&&at.compareTo(t.end())<=0;
    }

    /** Physical words, zero-extended lwzx entries and 32-bit address arithmetic.
     * No decompiler references or reconstructed source supply target values. */
    private static Table match(Program p,Address branch,Function owner)throws Exception {
        if(!p.getLanguage().isBigEndian()||owner==null||owner.getSymbol().getSource()!=SourceType.DEFAULT)return null;
        var memory=p.getMemory();var text=memory.getBlock(branch);Address guard=branch.subtract(28);
        if(text==null||!text.isRead()||!text.isInitialized()||!text.isExecute()||text.isWrite()||
            !text.contains(guard)||!text.contains(branch.add(3))||!owner.getBody().contains(guard,branch.add(3)))return null;
        int[] w=new int[8];for(int n=0;n<8;n++)w[n]=memory.getInt(guard.add(n*4L));
        if((w[1]&0xffff0003)!=0x41990000||(w[2]&0xffff0000)!=0x3d800000||
            (w[3]&0xffff0000)!=0x398c0000||(w[4]&0xfc1fffff)!=0x5400103a||
            w[5]!=0x7c0c002e||w[6]!=0x7c0903a6||w[7]!=0x4e800420)return null;
        int index=(w[4]>>>21)&31;
        if(index==12||(w[0]&0xffff0000)!=(0x2b000000|(index<<16)))return null;
        int count=(w[0]&65535)+1;if(count<2||count>MAX_CASES)return null;
        long tableValue=(((long)(short)w[2]<<16)+(short)w[3])&0xffffffffL;
        if(tableValue!=branch.getOffset()+4||tableValue+count*4L-1>0xffffffffL)return null;
        Address data=branch.add(4),end=data.add(count*4L-1);
        if((tableValue&3)!=0||!text.contains(end))return null;
        Address fallback=guard.add(4L+(short)(w[1]&0xfffc));
        if(fallback.compareTo(end)<=0||!text.contains(fallback)||!text.contains(fallback.add(3)))return null;
        var targets=new TreeSet<Address>();
        for(int n=0;n<count;n++) {
            long value=Integer.toUnsignedLong(memory.getInt(data.add(n*4L)));
            if((value&3)!=0)return null;Address target=branch.getAddressSpace().getAddress(value);
            if(target.compareTo(end)<=0||!text.contains(target)||!text.contains(target.add(3)))return null;
            targets.add(target);
        }
        // Stock follow-up may remove an ANALYSIS jump to the guard's default,
        // causing alternating remove/re-add passes. Keep that independently
        // understood but unstable alias outside this first automatic contract.
        if(targets.size()<2||targets.contains(fallback))return null;
        return new Table(branch,guard,data,end,fallback,count,index,targets);
    }

    /** Every rejection precedes the first database mutation. */
    private static Plan preflight(Program p,Function owner,Table t,TaskMonitor monitor)throws Exception {
        var listing=p.getListing();var refs=p.getReferenceManager();var old=owner.getBody();
        for(Address at=t.guard();at.compareTo(t.branch())<=0;at=at.add(4)) {
            monitor.checkCancelled();var i=listing.getInstructionAt(at);int n=(int)(at.subtract(t.guard())/4);
            require(i!=null&&i.getLength()==4&&i.getFlowOverride()==FlowOverride.NONE&&!i.isFallThroughOverridden(),"dispatch_instruction_or_override");
            require(n==7?i.getFallThrough()==null:at.add(4).equals(i.getFallThrough()),"dispatch_fallthrough");
            for(int b=0;b<4;b++) {
                Address byteAt=at.add(b);require(!protectedSymbol(p,byteAt)&&listing.getDefinedDataContaining(byteAt)==null,"protected_dispatch");
                require(owner.equals(p.getFunctionManager().getFunctionContaining(byteAt)),"dispatch_owner");
                if(!byteAt.equals(t.guard()))for(var r:refs.getReferencesTo(byteAt))
                    require(!r.getReferenceType().isFlow()||(b==0&&r.getFromAddress().equals(at.subtract(4))&&r.getReferenceType()==RefType.FALL_THROUGH),"guard_bypass");
            }
            for(var r:refs.getReferencesFrom(at))if(r.getReferenceType().isFlow()) {
                boolean allowed=n==7?r.getReferenceType().isJump()&&t.targets().contains(r.getToAddress()):
                    n==1&&r.getReferenceType().isConditional()&&r.getToAddress().equals(t.fallback());
                allowed|=n<7&&r.getReferenceType()==RefType.FALL_THROUGH&&r.getToAddress().equals(at.add(4));
                require(allowed,"conflicting_dispatch_reference");
            }
        }
        // Executable permission is not proof that these bytes are data. Exact inline
        // placement after non-fallthrough bctr, complete guard proof, no instruction,
        // owner, flow entry or protected symbol, and the graph below are all required.
        for(Address at=t.data();at.compareTo(t.end())<=0;at=at.add(1)) {
            monitor.checkCancelled();require(listing.getInstructionContaining(at)==null,"table_overlaps_instruction");
            require(p.getFunctionManager().getFunctionContaining(at)==null,"table_has_owner");
            require(!protectedSymbol(p,at),"protected_table_symbol");
            var d=listing.getDefinedDataContaining(at);
            if(d!=null)require(d.getLength()==4&&((d.getAddress().subtract(t.data())&3)==0)&&
                d.getAddress().compareTo(t.data())>=0&&d.getMaxAddress().compareTo(t.end())<=0&&
                (d.getDataType() instanceof Pointer||d.getDataType() instanceof DWordDataType),"incompatible_table_definition");
            for(var r:refs.getReferencesTo(at))require(!r.getReferenceType().isFlow(),"flow_into_table");
            for(var r:refs.getReferencesFrom(at)) {
                require(!r.getReferenceType().isFlow(),"flow_from_table");
                long offset=at.subtract(t.data());
                require((offset&3)==0&&r.getToAddress().getOffset()==Integer.toUnsignedLong(p.getMemory().getInt(at)),"conflicting_table_reference");
            }
        }
        var extra=new AddressSet();var queue=new ArrayDeque<Address>(t.targets());queue.add(t.fallback());
        var decoder=new PseudoDisassembler(p);var text=p.getMemory().getBlock(t.branch());
        while(!queue.isEmpty()) {
            monitor.checkCancelled();Address at=queue.removeFirst();
            require(!interior(t,at)&&!storage(t,at),"new_flow_bypasses_guard_or_enters_table");
            require((at.getOffset()&3)==0&&text.contains(at)&&text.contains(at.add(3)),"code_outside_executable_bounds");
            if(extra.contains(at))continue;
            var other=p.getFunctionManager().getFunctionContaining(at);
            require(other==null||other.equals(owner),"conflicting_target_owner");
            for(int b=0;b<4;b++) {
                require(!protectedSymbol(p,at.add(b))&&listing.getDefinedDataContaining(at.add(b))==null,"protected_target_symbol_or_data");
                var byteOwner=p.getFunctionManager().getFunctionContaining(at.add(b));
                require(byteOwner==null||byteOwner.equals(owner),"conflicting_target_owner");
            }
            Instruction i=listing.getInstructionContaining(at);
            require(i==null||(i.getAddress().equals(at)&&i.getLength()==4&&i.getFlowOverride()==FlowOverride.NONE&&!i.isFallThroughOverridden()),"target_instruction_or_override");
            if(old.contains(at)){require(i!=null&&old.contains(at,at.add(3)),"owned_target_not_instruction");continue;}
            require(extra.getNumAddresses()<MAX_EXTRA_BYTES&&at.compareTo(owner.getEntryPoint())>=0&&at.subtract(t.branch())<=MAX_EXTRA_BYTES,"caller_expansion_budget");
            if(i==null)try{i=decoder.disassemble(at);}catch(Exception ex){throw new Rejected("undecodable_target");}
            require(i!=null&&i.getLength()==4,"undecodable_target");var flow=i.getFlowType();
            require(!(flow.isJump()&&flow.isComputed()),"new_nested_or_unsupported_computed_jump");
            extra.add(at,at.add(3));
            for(Address to:i.getFlows()) {
                require(!interior(t,to)&&!storage(t,to),"new_flow_bypasses_guard_or_enters_table");
                if(flow.isJump()) {
                    if(!flow.isConditional()&&p.getFunctionManager().getFunctionAt(to)!=null&&!old.contains(to))continue;
                    queue.add(to);
                }
            }
            Address next=i.getFallThrough();
            if(flow.isCall())for(Address to:i.getFlows()){var callee=p.getFunctionManager().getFunctionAt(to);if(callee!=null&&callee.hasNoReturn())next=null;}
            if(next!=null)queue.add(next);
        }
        // An unowned range with an incoming edge from another graph is not free
        // caller code. Also reject jumps to the interior bytes of an instruction.
        var body=new AddressSet(old);body.add(extra);
        for(var range:extra.getAddressRanges())for(Address at=range.getMinAddress();at.compareTo(range.getMaxAddress())<=0;at=at.add(1))
            for(var r:refs.getReferencesTo(at))if(r.getReferenceType().isFlow())
                require((at.getOffset()&3)==0&&body.contains(r.getFromAddress())&&r.getSource()!=SourceType.USER_DEFINED&&r.getSource()!=SourceType.IMPORTED,"incompatible_incoming_flow");
        return new Plan(extra);
    }

    public static HalfwordSwitchRecovery.Result recover(Program p,Address branch,TaskMonitor monitor)throws Exception {
        var owner=p.getFunctionManager().getFunctionContaining(branch);Table t=match(p,branch,owner);if(t==null)return null;
        var evidence=new LinkedHashMap<String,Object>();evidence.put("binary_sha256",XenonEvidence.sourceHash(p));
        evidence.put("branch",branch.toString());evidence.put("function_address",owner.getEntryPoint().toString());
        evidence.put("table_address",t.data().toString());evidence.put("entry_count",t.count());evidence.put("entry_width",4);
        evidence.put("signed",false);evidence.put("endianness","big");evidence.put("target_calculation","zero_extend_uint32_entry");
        evidence.put("guard",t.guard().toString());evidence.put("fallback",t.fallback().toString());evidence.put("index_register",t.index());
        evidence.put("targets",t.targets().stream().map(Object::toString).toList());
        evidence.put("identification_source","exact unsigned cmplwi/bgt; lis/addi; r0=index*4; lwzx r0,r12,r0; mtctr r0; bctr; unreachable inline uint32 table");
        Plan plan;try{plan=preflight(p,owner,t,monitor);}catch(Rejected ex){evidence.put("status","withheld_ownership_or_data");evidence.put("rejection_reason",ex.getMessage());return new HalfwordSwitchRecovery.Result(1,0,0,evidence);}
        var starts=new AddressSet();for(var range:plan.extra().getAddressRanges())for(Address at=range.getMinAddress();at.compareTo(range.getMaxAddress())<=0;at=at.add(4)) {
            monitor.checkCancelled();if(p.getListing().getInstructionAt(at)==null)starts.add(at);
        }
        if(!starts.isEmpty()) {
            var command=new DisassembleCommand(starts,plan.extra(),false);command.enableCodeAnalysis(false);
            if(!command.applyTo(p,monitor)){monitor.checkCancelled();throw new IllegalStateException("Bounded absolute-word disassembly failed: "+command.getStatusMsg());}
        }
        for(var range:plan.extra().getAddressRanges())for(Address at=range.getMinAddress();at.compareTo(range.getMaxAddress())<=0;at=at.add(4)) {
            monitor.checkCancelled();var i=p.getListing().getInstructionAt(at);if(i==null||i.getLength()!=4)throw new IllegalStateException("Missing preflighted word-switch instruction at "+at);
        }
        int added=0;for(Address target:t.targets()) {
            monitor.checkCancelled();boolean present=false;for(var r:p.getReferenceManager().getReferencesFrom(branch))if(r.getReferenceType().isJump()&&r.getToAddress().equals(target)){present=true;break;}
            if(!present){p.getReferenceManager().addMemoryReference(branch,target,RefType.COMPUTED_JUMP,SourceType.ANALYSIS,-1);added++;}
        }
        var body=new AddressSet(owner.getBody());body.add(plan.extra());if(!plan.extra().isEmpty())owner.setBody(body);
        monitor.checkCancelled();if(added!=0||!plan.extra().isEmpty())AutoAnalysisManager.getAnalysisManager(p).codeDefined(body);
        evidence.put("status","validated_present");evidence.put("new_body_bytes",plan.extra().getNumAddresses());evidence.put("direct_call_code_bytes",0);
        evidence.put("validated_dispatches",List.of(branch.toString()));
        return new HalfwordSwitchRecovery.Result(1,plan.extra().isEmpty()?0:1,added,evidence);
    }
}
