package xenon360.analysis;

import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.PseudoDisassembler;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/** Bounded CFG preflight before creating an unowned, independently validated callback.
 * No clearing, owner changes, arbitrary tail traversal, or inferred prototypes.
 */
public final class ValidatedCallbackRecovery {
    private ValidatedCallbackRecovery() {}
    public static boolean create(Program p,Address entry,TaskMonitor monitor) throws Exception {
        if(p.getFunctionManager().getFunctionContaining(entry)!=null)return false;
        if(Arrays.stream(p.getSymbolTable().getSymbols(entry)).anyMatch(s->s.getSource()!=SourceType.DEFAULT))return false;
        var block=p.getMemory().getBlock(entry);
        if(block==null || !block.isExecute() || !block.isInitialized())return false;
        var decoder=new PseudoDisassembler(p);var body=new AddressSet();
        var queue=new ArrayDeque<Address>();queue.add(entry);boolean terminal=false;
        while(!queue.isEmpty()) {
            monitor.checkCancelled();Address at=queue.removeFirst();
            if(body.contains(at))continue;
            if(body.getNumAddresses()>=256 || at.compareTo(entry)<0 || at.subtract(entry)>252 ||
                !block.contains(at) || !block.contains(at.add(3)) || (at.getOffset()&3)!=0 ||
                p.getFunctionManager().getFunctionContaining(at)!=null || p.getListing().getDefinedDataContaining(at)!=null ||
                p.getListing().getDefinedData(new AddressSet(at,at.add(3)),true).hasNext())return false;
            var existing=p.getListing().getInstructionContaining(at);
            if(existing!=null && !existing.getAddress().equals(at))return false;
            Instruction instruction=existing;
            if(instruction==null) {
                try {instruction=decoder.disassemble(at);} catch(Exception unsupported) {return false;}
            }
            if(instruction==null || instruction.getLength()!=4)return false;
            body.add(at,at.add(3));
            var flow=instruction.getFlowType();
            if(flow.isTerminal() || (flow.isJump() && flow.isComputed()))terminal=true;
            if(flow.isJump() && !flow.isComputed())for(var target:instruction.getFlows()) {
                // Shared-return analysis can later reclassify this exact branch as a
                // tail call. Recognize the established entry now so the first pass
                // and a rerun see the same bounded callback body. Interior targets
                // and unresolved external branches still fail the normal preflight.
                if(!flow.isConditional() && !target.equals(entry) &&
                    p.getFunctionManager().getFunctionAt(target)!=null) terminal=true;
                else queue.add(target);
            }
            if(instruction.getFallThrough()!=null)queue.add(instruction.getFallThrough());
        }
        if(!terminal)return false;
        var disassemble=new DisassembleCommand(entry,body,true);disassemble.enableCodeAnalysis(false);
        if(!disassemble.applyTo(p,monitor)) {
            monitor.checkCancelled();
            throw new IllegalStateException("Validated callback disassembly failed at "+entry+
                "; roll back the analysis transaction: "+disassemble.getStatusMsg());
        }
        monitor.checkCancelled();
        p.getFunctionManager().createFunction(null,entry,body,SourceType.ANALYSIS);
        return true;
    }
}
