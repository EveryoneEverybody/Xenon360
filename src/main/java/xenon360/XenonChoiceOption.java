package xenon360;

import java.awt.Component;
import java.util.Arrays;

import javax.swing.JComboBox;

import ghidra.app.util.Option;

/** String loader option presented as a fixed choice in the import dialog. */
final class XenonChoiceOption extends Option {
    private final String[] choices;

    XenonChoiceOption(String name, String defaultValue, String arg, String... choices) {
        super(name, String.class, defaultValue, arg, null);
        if (choices.length == 0 || Arrays.stream(choices).noneMatch(defaultValue::equals)) {
            throw new IllegalArgumentException("Default value must be one of the available choices");
        }
        this.choices = choices.clone();
    }

    @Override
    public Component getCustomEditorComponent() {
        JComboBox<String> combo = new JComboBox<>(choices);
        combo.setSelectedItem(getValue());
        combo.addActionListener(e -> setValue(combo.getSelectedItem()));
        return combo;
    }

    @Override
    public Option copy() {
        return new XenonChoiceOption(
            getName(), (String) getValue(), getArg(), choices);
    }
}
