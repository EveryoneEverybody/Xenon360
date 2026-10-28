package xenon360;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/** Re-runnable helper modeling with a conservative ownership preflight. */
public final class XenonCompilerHelperAnalyzer extends AbstractAnalyzer {
    public static final String NAME="Xenon360 Compiler Helpers";
    private static final String REPAIR="Repair CALL_RETURN at exact save helpers";
    private boolean repair;
    public XenonCompilerHelperAnalyzer() {
        super(NAME,"Model exact compiler save helpers. Existing function ownership and symbols are preserved.",AnalyzerType.BYTE_ANALYZER);
        setPriority(AnalysisPriority.FORMAT_ANALYSIS.before());
        setDefaultEnablement(true); setSupportsOneTimeAnalysis();
    }
    @Override public boolean canAnalyze(Program p) {
        return p.getLanguageID().toString().equals("PowerPC:BE:64:Xenon-VMX128-32addr");
    }
    @Override public void registerOptions(Options options,Program p) {
        options.registerOption(REPAIR,false,null,"Advanced: clear CALL_RETURN overrides only on direct calls to exact modeled save helpers. Ghidra does not record override authorship; leave disabled to preserve manual overrides.");
    }
    @Override public void optionsChanged(Options options,Program p) {repair=options.getBoolean(REPAIR,false);}
    @Override public boolean added(Program p,AddressSetView set,TaskMonitor monitor,MessageLog log) throws CancelledException {
        if(!set.contains(p.getMemory())) return false;
        int transaction=p.startTransaction(NAME);
        boolean commit=false;
        try {
            var result=XenonCompilerHelperBootstrap.apply(p,monitor);
            int residuals=0,repaired=0;
            var functions=p.getFunctionManager().getFunctions(true);
            while(functions.hasNext()) {
                monitor.checkCancelled();
                var f=functions.next();
                if(!"xenon_ppc_savegpr_noop".equals(f.getCallFixup())) continue;
                var refs=p.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while(refs.hasNext()) {
                    monitor.checkCancelled();
                    var ref=refs.next();
                    if(!ref.getReferenceType().isCall()) continue;
                    var inst=p.getListing().getInstructionAt(ref.getFromAddress());
                    if(inst==null || inst.getFlowOverride()!=FlowOverride.CALL_RETURN) continue;
                    residuals++;
                    if(!repair) continue;
                    // Instruction bytes must independently establish a direct linked branch.
                    int word=p.getMemory().getInt(inst.getAddress(),true);
                    if((word&0xfc000001)!=0x48000001) continue;
                    long disp=(word&0x03fffffc); if((disp&0x02000000)!=0) disp-=0x04000000;
                    long target=((word&2)!=0?disp:inst.getAddress().getOffset()+disp)&0xffffffffL;
                    if(target!=f.getEntryPoint().getOffset()) continue;
                    inst.setFlowOverride(FlowOverride.NONE); repaired++;
                }
            }
            p.getOptions("Xenon360").setInt("Helper ownership conflicts withheld",result.withheldFamilies());
            p.getOptions("Xenon360").setInt("Helper CALL_RETURN residuals",residuals-repaired);
            String summary="families="+result.families()+";entries="+result.entries()+";created="+result.createdFunctions()+
                ";withheld_families="+result.withheldFamilies()+";residuals="+(residuals-repaired)+";repaired="+repaired;
            p.getOptions("Xenon360").setString("Helper analysis summary",summary);
            commit=true;
            Msg.info(this,summary);
            return true;
        } catch(CancelledException ex) {throw ex;}
        catch(Exception ex) {log.appendMsg(NAME,"Helper analysis rolled back: "+ex.getMessage());log.appendException(ex);return false;}
        finally {p.endTransaction(transaction,commit);}
    }
}
