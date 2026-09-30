package xenon360;

import java.awt.BorderLayout;
import java.awt.Component;
import java.io.File;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JTextField;

import docking.widgets.button.BrowseButton;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.textfield.ElidingFilePathTextField;
import ghidra.app.util.Option;
import ghidra.framework.options.SaveState;
import ghidra.util.filechooser.ExtensionFileFilter;

/**
 * Loader option that keeps headless string arguments while presenting a normal
 * filesystem picker in Ghidra's import dialog.
 */
final class XenonFilePathOption extends Option {
    private static final String STATE_KEY = "Xenon360.Loader.Files";

    private final String dialogTitle;
    private final String approveText;
    private final String filterDescription;
    private final String[] extensions;
    XenonFilePathOption(String name, String arg, String dialogTitle,
            String approveText, String filterDescription, String... extensions) {
        this(name, arg, "", dialogTitle, approveText, filterDescription, extensions);
    }

    private XenonFilePathOption(String name, String arg, String value,
            String dialogTitle, String approveText, String filterDescription,
            String... extensions) {
        super(name, String.class, value, arg, null, STATE_KEY, false);
        this.dialogTitle = dialogTitle;
        this.approveText = approveText;
        this.filterDescription = filterDescription;
        this.extensions = extensions.clone();
    }

    @Override
    public Component getCustomEditorComponent() {
        SaveState state = getState();
        String current = (String) getValue();
        String remembered = state == null ? current :
            state.getString(getName(), current);
        if (remembered == null) {
            remembered = "";
        }
        setValue(remembered);

        JTextField field = new ElidingFilePathTextField(remembered);
        field.setEditable(false);
        field.setColumns(20);
        BrowseButton browse = new BrowseButton();
        browse.setToolTipText("Choose file");
        browse.addActionListener(e -> {
            GhidraFileChooser chooser = new GhidraFileChooser(field);
            try {
                String value = (String) getValue();
                if (value != null && !value.isBlank()) {
                    chooser.setSelectedFile(new File(value));
                }
                chooser.setTitle(dialogTitle);
                chooser.setApproveButtonText(approveText);
                chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
                if (extensions.length != 0) {
                    chooser.setFileFilter(
                        new ExtensionFileFilter(extensions, filterDescription));
                }
                File file = chooser.getSelectedFile();
                if (!chooser.wasCancelled() && file != null) {
                    String path = file.getAbsolutePath();
                    field.setText(path);
                    setValue(path);
                    if (state != null) {
                        state.putString(getName(), path);
                    }
                }
            }
            finally {
                chooser.dispose();
            }
        });

        JButton clear = new JButton("Clear");
        clear.setToolTipText("Clear selected file");
        clear.addActionListener(e -> {
            field.setText("");
            setValue("");
            if (state != null) {
                state.putString(getName(), "");
            }
        });

        JPanel buttons = new JPanel();
        buttons.add(browse);
        buttons.add(clear);

        JPanel panel = new JPanel(new BorderLayout(5, 0));
        panel.add(field, BorderLayout.CENTER);
        panel.add(buttons, BorderLayout.EAST);
        return panel;
    }

    @Override
    public Option copy() {
        return new XenonFilePathOption(
            getName(), getArg(), (String) getValue(), dialogTitle,
            approveText, filterDescription, extensions);
    }
}
