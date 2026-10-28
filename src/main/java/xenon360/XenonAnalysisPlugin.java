package xenon360;

import java.io.File;
import java.nio.file.Files;
import com.google.gson.JsonParser;
import docking.action.builder.ActionBuilder;
import docking.widgets.filechooser.*;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.*;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.task.*;
import xenon360.analysis.*;

@PluginInfo(status=PluginStatus.RELEASED,packageName=CorePluginPackage.NAME,
    category=PluginCategoryNames.ANALYSIS,shortDescription="Xenon360 analysis evidence",
    description="Export Havok and import evidence and compare independently identified binaries with native BSim features.")
public final class XenonAnalysisPlugin extends ProgramPlugin {
    public XenonAnalysisPlugin(PluginTool tool) {
        super(tool);
        new ActionBuilder("Export Xenon360 Analysis Evidence",getName())
            .menuPath("Tools","Xenon360","Export Analysis Evidence...")
            .description("Export binary identities, validated Havok structures, import provenance and BSim features")
            .enabledWhen(c->currentProgram!=null).onAction(c->runExport(false)).buildAndInstall(tool);
        new ActionBuilder("Compare Xenon360 Reference Evidence",getName())
            .menuPath("Tools","Xenon360","Compare Reference Evidence...")
            .description("Compare a reference export with the current program; no names or types are transferred")
            .enabledWhen(c->currentProgram!=null).onAction(c->runExport(true)).buildAndInstall(tool);
    }
    private File choose(String title,String approve) {
        var chooser=new GhidraFileChooser(tool.getToolFrame());
        try {
            chooser.setTitle(title);chooser.setApproveButtonText(approve);
            chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
            chooser.setFileFilter(new ExtensionFileFilter(new String[]{"json"},"Xenon360 JSON evidence"));
            File file=chooser.getSelectedFile();return chooser.wasCancelled()?null:file;
        } finally {chooser.dispose();}
    }
    private void runExport(boolean compare) {
        var program=currentProgram;
        if(program==null)return;
        File reference=compare?choose("Choose reference evidence","Open"):null;
        if(compare && reference==null)return;
        File output=choose(compare?"Save comparison evidence":"Save analysis evidence","Save");
        if(output==null)return;
        program.addConsumer(this);
        new TaskLauncher(new Task("Xenon360 analysis evidence",true,true,true) {
            @Override public void run(TaskMonitor monitor) {
                try {
                    var report=XenonEvidence.collect(program,true,monitor);
                    Object result=report;
                    if(compare) {
                        if(Files.size(reference.toPath())>16*1024*1024)throw new IllegalArgumentException("Reference JSON exceeds 16 MiB");
                        var ref=JsonParser.parseString(Files.readString(reference.toPath())).getAsJsonObject();
                        result=CrossArchitectureMatcher.compare(ref,XenonEvidence.JSON.toJsonTree(report).getAsJsonObject(),monitor);
                    }
                    monitor.checkCancelled();XenonEvidence.writeAtomic(output.toPath(),result);
                    tool.setStatusInfo("Xenon360 evidence saved: "+output.getAbsolutePath());
                } catch(CancelledException cancelled) {tool.setStatusInfo("Xenon360 evidence export cancelled");}
                catch(Exception ex) {Msg.showError(this,tool.getToolFrame(),"Xenon360 evidence export",ex.getMessage(),ex);}
                finally {program.release(XenonAnalysisPlugin.this);}
            }
        },tool.getToolFrame());
    }
}
