import java.nio.file.*;
import xenon360.xex.XexImage;

/** Local-only research extraction; output is never packaged in the extension. */
public class XexCorpusProbe {
    public static void main(String[] args) throws Exception {
        Path source = Path.of(args[0]), output = Path.of(args[1]);
        XexImage image = XexImage.parse(Files.readAllBytes(source));
        Files.createDirectories(output);
        Files.write(output.resolve("image.bin"), image.image);
        StringBuilder json = new StringBuilder("{\n  \"source_sha256\": \"")
            .append(image.sourceSha256).append("\",\n  \"image_sha256\": \"")
            .append(XexImage.sha256(image.image)).append("\",\n  \"base\": ")
            .append(image.imageBase).append(",\n  \"entry\": ").append(image.entryPoint)
            .append(",\n  \"sections\": [");
        boolean first = true;
        for (var section : image.sections) {
            if (!first) json.append(',');
            first = false;
            json.append(String.format(java.util.Locale.ROOT,
                "\n    {\"name\":\"%s\",\"rva\":%d,\"size\":%d,\"execute\":%s}",
                section.name(), section.rva(), section.size(), section.execute()));
        }
        json.append("\n  ]\n}\n");
        Files.writeString(output.resolve("identity.json"), json);
        System.out.println(source + " sha256=" + image.sourceSha256 + " base=" +
            Long.toHexString(image.imageBase) + " imports=" + image.libraries.size());
    }
}
