package xenon360;

import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.CancelledException;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.*;
import xenon360.havok.HavokMetadata;

/** Safe metadata recognition is automatic; callback naming is an explicit advanced option. */
public final class XenonHavokAnalyzer extends AbstractAnalyzer {
    public static final String NAME="Xenon360 Havok Metadata";
    private static final String RENAME="Name validated callback functions";
    private static final String RECOVER="Create unowned validated callback functions";
    private boolean rename;
    private boolean recover=true;
    public XenonHavokAnalyzer() {
        super(NAME,"Validate Havok metadata and preserve evidence. Does not infer SDK version from layout.",AnalyzerType.BYTE_ANALYZER);
        setDefaultEnablement(true);
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setSupportsOneTimeAnalysis();
    }
    @Override public boolean canAnalyze(Program p) {
        return p.getLanguageID().toString().equals("PowerPC:BE:64:Xenon-VMX128-32addr");
    }
    @Override public void registerOptions(Options options,Program p) {
        options.registerOption(RENAME,false,null,"Name only unique validated callbacks at existing default-named function entries. Never overwrite established symbols.");
        options.registerOption(RECOVER,true,null,"Recover only unowned, validated callbacks with a complete CFG within 256 bytes. Never change existing ownership or clear code/data.");
    }
    @Override public void optionsChanged(Options options,Program p) {rename=options.getBoolean(RENAME,false);recover=options.getBoolean(RECOVER,true);}
    @Override public boolean added(Program p,AddressSetView set,TaskMonitor monitor,MessageLog log) throws CancelledException {
        if(!set.contains(p.getMemory())) return false;
        try {
            var result=HavokMetadata.scan(XenonEvidence.snapshot(p,monitor),monitor);
            int labels=0,renamed=0,created=0;
            int transaction=p.startTransaction(NAME);
            boolean commit=false;
            try {
                for(var t:result.types()) {
                    monitor.checkCancelled();
                    Address at=p.getAddressFactory().getDefaultAddressSpace().getAddress(t.address());
                    String name=HavokMetadata.snake(t.className())+"_type_info";
                    boolean protectedSymbol=java.util.Arrays.stream(p.getSymbolTable().getSymbols(at))
                        .anyMatch(s->s.getSource()!=SourceType.DEFAULT &&
                            !(s.getSource()==SourceType.ANALYSIS && s.getName().equals(name)));
                    if(protectedSymbol) continue;
                    var primary=p.getSymbolTable().getPrimarySymbol(at);
                    if(primary!=null && primary.getSource()!=SourceType.DEFAULT && !primary.getName().equals(name)) continue;
                    if(primary==null || !primary.getName().equals(name)) {
                        p.getSymbolTable().createLabel(at,name,SourceType.ANALYSIS); labels++;
                    }
                    int count=t.profile().equals(HavokMetadata.LEGACY)?4:6;
                    if(p.getListing().isUndefined(at,at.add(count*4L-1))) {
                        var dt=new StructureDataType(new CategoryPath("/Xenon360/Havok"),t.profile()+"32",0);
                        String[] fields=count==4?new String[]{"name","finish","cleanup","vtable"}:
                            new String[]{"name","scoped_name","finish","cleanup","vtable","object_size"};
                        for(String field:fields) dt.add(field.equals("object_size")?UnsignedIntegerDataType.dataType:
                            new PointerDataType(null,4),field,null);
                        DataType existing=p.getDataTypeManager().getDataType(dt.getCategoryPath(),dt.getName());
                        if(existing==null || existing.isEquivalent(dt)) p.getListing().createData(at,dt);
                    }
                }
                if(recover && !XenonEvidence.sourceHash(p).equals("UNKNOWN")) {
                    for(var row:XenonEvidence.functions(p,result)) {
                        monitor.checkCancelled();
                        if(!row.get("confidence").equals("high") || !row.get("status").equals("withheld_function_boundary"))continue;
                        if(ValidatedCallbackRecovery.create(p,p.getAddressFactory().getAddress((String)row.get("address")),monitor))created++;
                    }
                }
                if(rename && !XenonEvidence.sourceHash(p).equals("UNKNOWN")) {
                    for(var row:XenonEvidence.functions(p,result)) {
                        monitor.checkCancelled();
                        if(!row.get("status").equals("withheld_auto_rename_disabled")) continue;
                        Address at=p.getAddressFactory().getAddress((String)row.get("address"));
                        Function f=p.getFunctionManager().getFunctionAt(at);
                        boolean protectedSymbol=java.util.Arrays.stream(p.getSymbolTable().getSymbols(at))
                            .anyMatch(s->s.getSource()!=SourceType.DEFAULT);
                        if(protectedSymbol) continue;
                        f.setName((String)row.get("recommended_name"),SourceType.ANALYSIS);
                        p.getOptions("Xenon360").setString("Havok applied name "+row.get("address"),(String)row.get("recommended_name"));
                        renamed++;
                    }
                }
                Options info=p.getOptions("Xenon360");
                info.setInt("Havok validated type info",result.types().size());
                info.setInt("Havok validated class descriptors",result.classes().size());
                info.setBoolean("Havok scan limited",result.limited());
                info.setString("Havok version markers",result.versions().stream().map(HavokMetadata.Version::marker).distinct().sorted().reduce((a,b)->a+";"+b).orElse("UNKNOWN"));
                commit=true;
            } finally {p.endTransaction(transaction,commit);}
            Msg.info(this,"validated_type_info="+result.types().size()+";hk_class="+result.classes().size()+
                ";new_labels="+labels+";created_callbacks="+created+";renamed="+renamed+";rejected="+result.rejectedPointerCandidates()+";limited="+result.limited());
            return true;
        } catch(CancelledException ex) {throw ex;}
        catch(Exception ex) {log.appendMsg(NAME,"Havok analysis failed: "+ex.getMessage());log.appendException(ex);return false;}
    }
}
