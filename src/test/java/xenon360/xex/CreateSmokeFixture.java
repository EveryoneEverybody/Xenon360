package xenon360.xex;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.zip.ZipFile;

/** Creates an isolated extension installation and a synthetic executable for integration tests. */
public final class CreateSmokeFixture implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        Path root = Path.of(args[1]).toAbsolutePath().normalize();
        Path settings = layout.getUserSettingsDir().toPath().toAbsolutePath().normalize();
        if (!settings.startsWith(root)) {
            throw new IllegalStateException("Smoke test settings are not isolated: " + settings);
        }
        Path extensions = settings.resolve("Extensions");
        Files.createDirectories(extensions);
        try (ZipFile zip = new ZipFile(args[0])) {
            var entries = zip.entries();
            while (entries.hasMoreElements()) {
                var entry = entries.nextElement();
                Path target = extensions.resolve(entry.getName()).normalize();
                if (!target.startsWith(extensions)) { throw new IllegalArgumentException("Unsafe ZIP path"); }
                if (entry.isDirectory()) { Files.createDirectories(target); continue; }
                Files.createDirectories(target.getParent());
                try (var input = zip.getInputStream(entry)) {
                    Files.copy(input, target, StandardCopyOption.REPLACE_EXISTING);
                    Files.setLastModifiedTime(target, entry.getLastModifiedTime());
                }
            }
        }
        byte[] fixture = XexImageSelfTest.fixture(0, "none");
        ByteBuffer be = ByteBuffer.wrap(fixture).order(ByteOrder.BIG_ENDIAN);
        ByteBuffer le = ByteBuffer.wrap(fixture).order(ByteOrder.LITTLE_ENDIAN);
        int payload = 0x1000;
        int section = payload + 0x80 + 24 + 224;
        le.putInt(section + 8, 0x300);
        le.putInt(section + 16, 0x300);
        be.putInt(payload + 0x1000, 0x7d8802a6); // mflr r12
        be.putInt(payload + 0x1004, 0x480000fd); // bl 0x82001100
        be.putInt(payload + 0x1008, 0x4e800020); // blr
        for (int reg = 14; reg <= 31; reg++) {
            int displacement = (-0x98 + (reg - 14) * 8) & 0xffff;
            be.putInt(payload + 0x1100 + (reg - 14) * 4, 0xf8000000 | reg << 21 | 1 << 16 | displacement);
            be.putInt(payload + 0x1150 + (reg - 14) * 4, 0xe8000000 | reg << 21 | 1 << 16 | displacement);
        }
        be.putInt(payload + 0x1148, 0x9181fff8);
        be.putInt(payload + 0x114c, 0x4e800020);
        be.putInt(payload + 0x1198, 0x8181fff8);
        be.putInt(payload + 0x119c, 0x7d8803a6);
        be.putInt(payload + 0x11a0, 0x4e800020);
        be.putInt(payload + 0x1200, 0x150d6150); // vnmsubfp128
        be.putInt(payload + 0x1204, 0x1674aa75); // vandc128
        be.putInt(payload + 0x1208, 0x1b6ce185); // vcmpbfp128
        Files.write(root.resolve("synthetic.xex"), fixture);
        Files.createDirectories(root.resolve("project"));
        System.out.println("Created isolated Xenon360 smoke-test installation.");
    }
}
