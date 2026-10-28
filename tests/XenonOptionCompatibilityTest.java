import ghidra.app.script.GhidraScript;
import ghidra.app.util.Option;
import java.awt.Component;
import java.awt.Container;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.SwingUtilities;

/** Exercise the installed Ghidra editor dispatch, copy and clear contracts. */
public class XenonOptionCompatibilityTest extends GhidraScript {
    private Component editor(Option option) throws Exception {
        var method=Arrays.stream(Option.class.getMethods())
            .filter(m->m.getName().equals("getCustomEditorComponent")).findFirst().orElseThrow();
        return (Component)method.invoke(option,new Object[method.getParameterCount()]);
    }
    private JButton clear(Component c) {
        if(c instanceof JButton b && "Clear".equals(b.getText()))return b;
        if(c instanceof Container group)for(Component child:group.getComponents()) {
            JButton found=clear(child);if(found!=null)return found;
        }
        return null;
    }
    @Override protected void run() throws Exception {
        Exception[] failure={null};
        SwingUtilities.invokeAndWait(()->{try {
            var choiceCtor=Class.forName("xenon360.XenonChoiceOption").getDeclaredConstructors()[0];
            choiceCtor.setAccessible(true);
            Option choice=(Option)choiceCtor.newInstance("Mode","public-symbols","mode",new String[]{"public-symbols","all"});
            if(!(editor(choice) instanceof JComboBox<?> combo))throw new AssertionError("Missing fixed-choice editor");
            combo.setSelectedItem("all");
            if(!choice.getValue().equals("all") || !choice.copy().getValue().equals("all"))throw new AssertionError("Choice copy/value");
            var fileCtor=Arrays.stream(Class.forName("xenon360.XenonFilePathOption").getDeclaredConstructors())
                .filter(c->c.getParameterCount()==6).findFirst().orElseThrow();
            fileCtor.setAccessible(true);
            Option file=(Option)fileCtor.newInstance("Test file","testFile","Choose file","Open","Symbols",new String[]{"pdb"});
            Component component=editor(file);
            file.setValue("synthetic file.pdb");
            if(!file.copy().getValue().equals(file.getValue()))throw new AssertionError("File copy/value");
            JButton button=clear(component);if(button==null)throw new AssertionError("Missing Clear control");
            button.doClick();if(!file.getValue().equals(""))throw new AssertionError("Clear did not clear value");
        }catch(Exception ex){failure[0]=ex;}});
        if(failure[0]!=null)throw failure[0];
        Files.writeString(Path.of(getScriptArgs()[0]),"{\"result\":\"PASS\",\"checks\":5}\n");
        println("XENON_OPTION_COMPATIBILITY_PASS");
    }
}
