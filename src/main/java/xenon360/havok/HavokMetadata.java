package xenon360.havok;

import java.util.*;
import java.util.regex.Pattern;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.analysis.BinaryImage;

/** Structural recognition, with explicit version/layout separation. No SDK payloads. */
public final class HavokMetadata {
    public static final String LEGACY = "hk_type_info_four_pointer";
    public static final String SCOPED = "hk_type_info_scoped_six_field";
    private static final Pattern CLASS_NAME = Pattern.compile("hk[a-z]{0,4}[A-Z][A-Za-z0-9_:]{1,120}");
    private static final Pattern VERSION = Pattern.compile("(?:Havok-|hk_)(?:[0-9]{1,4}\\.){2}[0-9]+-[A-Za-z0-9$]{1,8}");
    public record Version(String address, String marker) {}
    public record TypeInfo(long address, String className, String profile, long finish,
            long cleanup, long vtable, long objectSize, List<String> evidence) {}
    public record Member(String name, int offset, int type, int subtype, int count) {}
    public record ClassInfo(long address, String className, long parent, int objectSize,
            List<Member> members, List<String> evidence) {}
    public record Result(List<Version> versions, List<TypeInfo> types, List<ClassInfo> classes,
            int nameStrings, int rejectedPointerCandidates, boolean limited) {}

    private HavokMetadata() {}

    public static Result scan(BinaryImage image, TaskMonitor monitor) throws CancelledException {
        monitor.checkCancelled();
        Map<Long, String> names = new HashMap<>();
        List<Version> versions = new ArrayList<>();
        boolean limited = false;
        long total = image.segments.stream().filter(s -> !s.executable()).mapToLong(s -> s.bytes().length).sum();
        monitor.initialize(total * 2);
        long progress = 0;
        for (var s : image.segments) {
            if (s.executable()) continue;
            byte[] bytes = s.bytes();
            for (int offset = 0; offset < bytes.length; offset++) {
                if ((offset & 4095) == 0) { monitor.checkCancelled(); monitor.setProgress(progress + offset); }
                if (offset > 0 && bytes[offset - 1] != 0) continue;
                if (bytes[offset] != 'h' && bytes[offset] != 'H') continue;
                String text = image.string(s.address() + offset, 128);
                if (text == null) continue;
                if (VERSION.matcher(text).matches()) versions.add(new Version(BinaryImage.address(s.address()+offset), text));
                if (CLASS_NAME.matcher(text).matches()) {
                    if (names.size() >= 100000) { limited = true; break; }
                    names.put(s.address() + offset, text);
                }
            }
            progress += bytes.length;
            if (limited) break;
        }
        List<TypeInfo> types = new ArrayList<>();
        List<ClassInfo> classes = new ArrayList<>();
        int rejected = 0;
        int width = image.pointerSize;
        for (var s : image.segments) {
            if (s.executable()) continue;
            long start = (s.address() + width - 1) & -((long)width);
            for (long at = start; at + width * 4L <= s.end(); at += width) {
                if (((at - start) & 4095) == 0) { monitor.checkCancelled(); monitor.setProgress(progress + at - start); }
                String name = names.get(image.pointer(at));
                if (name == null) continue;
                TypeInfo type = readType(image, at, name);
                if (type != null) types.add(type);
                // hkClass here is a separately validated 32-bit format, not a PC layout copy.
                ClassInfo cls = width == 4 ? readClass(image, at, name) : null;
                if (cls != null) classes.add(cls);
                if (type == null && cls == null) rejected++;
                if (types.size() + classes.size() >= 10000) { limited = true; break; }
            }
            progress += s.bytes().length;
            if (limited) break;
        }
        // Reject disconnected or cyclic class-parent graphs. Self pointers are never inheritance.
        Map<Long, ClassInfo> byAddress = new HashMap<>();
        for (ClassInfo c : classes) byAddress.put(c.address, c);
        classes.removeIf(c -> !validParent(c, byAddress, new HashSet<>()));
        if(!limited && image.pointerSize==8 && !image.bigEndian && !image.powerPc)
            types.addAll(HavokStaticInitializers.scan(image,names,monitor));
        if(types.size()>10000) {types=new ArrayList<>(types.subList(0,10000));limited=true;}
        types.sort(Comparator.comparingLong(TypeInfo::address));
        return new Result(List.copyOf(versions), List.copyOf(types), List.copyOf(classes), names.size(), rejected, limited);
    }

    private static TypeInfo readType(BinaryImage m, long at, String name) {
        int w = m.pointerSize;
        String scoped = m.string(m.pointer(at + w), 128);
        if (scoped != null && scoped.startsWith("!") &&
                scoped.substring(1).replace("::", "").equals(name.replace("::", ""))) {
            if (m.segment(at, w * 6) == null) return null;
            long finish = m.pointer(at + w * 2L), cleanup = m.pointer(at + w * 3L);
            long vtable = m.pointer(at + w * 4L), size = m.pointer(at + w * 5L);
            if (!m.executable(cleanup) || (finish != 0 && !m.executable(finish)) || size <= 0 || size > 0x100000) return null;
            if (vtable != 0 && !validVtable(m, vtable)) return null;
            return new TypeInfo(at, name, SCOPED, finish, cleanup, vtable, size,
                List.of("exact unscoped/scoped name relationship", "executable cleanup and optional finish pointers",
                    "bounded target object size", vtable == 0 ? "nonvirtual metadata" : "mapped vtable with executable first entry"));
        }
        long finish = m.pointer(at + w), cleanup = m.pointer(at + w * 2L), vtable = m.pointer(at + w * 3L);
        // Four pointers alone are insufficient: require an independently decoded vtable store.
        if (!m.powerPc || w != 4 || !m.executable(finish) || !m.executable(cleanup) || !validVtable(m, vtable)) return null;
        if (!hasVtableStore(m, finish, vtable)) return null;
        return new TypeInfo(at, name, LEGACY, finish, cleanup, vtable, -1,
            List.of("four-pointer layout agrees with archived 6.5/6.6 hkTypeInfo declarations",
                "both callbacks in executable memory", "mapped vtable with executable first entry",
                "finish callback contains adjacent lis/addi/stw of this exact vtable to object+0"));
    }

    private static boolean validVtable(BinaryImage m, long at) {
        var segment = m.segment(at, m.pointerSize);
        return at != 0 && (at & (m.pointerSize - 1)) == 0 && segment != null &&
            !segment.executable() && m.executable(m.pointer(at));
    }

    /** Exact three-instruction local data-flow anchor; no caller ABI propagation. */
    public static boolean hasVtableStore(BinaryImage m, long function, long vtable) {
        for (int i = 0; i < 32; i++) {
            long at = function + i * 4L;
            if (!m.executable(at + 8)) return false;
            int a = (int)m.unsigned(at, 4);
            if (a == 0x4e800020 || (a >>> 26) == 18) return false;
            if (a >>> 26 != 15 || ((a >>> 16) & 31) != 0) continue;
            int b = (int)m.unsigned(at + 4, 4), c = (int)m.unsigned(at + 8, 4);
            if (b >>> 26 != 14 || c >>> 26 != 36) continue;
            if (((a >>> 21) & 31) != ((b >>> 16) & 31) ||
                    ((b >>> 21) & 31) != ((c >>> 21) & 31) || (c & 0x1fffff) != 0x30000) continue;
            long value = (((long)(short)a << 16) + (short)b) & 0xffffffffL;
            if (value == vtable) return true;
        }
        return false;
    }

    private static ClassInfo readClass(BinaryImage m, long at, String name) {
        if (m.segment(at, 48) == null) return null;
        long parent = m.pointer(at + 4), size = m.unsigned(at + 8, 4);
        long interfaces = m.unsigned(at + 12, 4), enums = m.pointer(at + 16), enumCount = m.unsigned(at + 20, 4);
        long members = m.pointer(at + 24), count = m.unsigned(at + 28, 4);
        if (size <= 0 || size > 0x100000 || interfaces > 16 || enumCount > 128 || count > 512 || count == 0) return null;
        if ((enumCount == 0) != (enums == 0) || (enumCount > 0 && m.segment(enums, (int)enumCount * 20) == null)) return null;
        if (members == 0 || (members & 3) != 0 || m.segment(members, (int)count * 24) == null) return null;
        if (parent != 0 && (parent == at || m.segment(parent, 48) == null)) return null;
        if (m.unsigned(at + 44, 4) > 65535) return null;
        List<Member> list = new ArrayList<>();
        Set<String> memberNames = new HashSet<>();
        for (int i = 0; i < count; i++) {
            long p = members + i * 24L;
            String mn = m.string(m.pointer(p), 128);
            int type = (int)m.unsigned(p + 12, 1), sub = (int)m.unsigned(p + 13, 1);
            int array = (int)m.unsigned(p + 14, 2), offset = (int)m.unsigned(p + 18, 2);
            if (mn == null || !mn.matches("[A-Za-z_][A-Za-z0-9_]{0,127}") || !memberNames.add(mn) ||
                    type <= 0 || type > 35 || sub > 35 || array > 4096 || offset >= size) return null;
            long cls = m.pointer(p + 4), en = m.pointer(p + 8);
            if ((cls != 0 && m.segment(cls, 48) == null) || (en != 0 && m.segment(en, 20) == null)) return null;
            list.add(new Member(mn, offset, type, sub, array));
        }
        return new ClassInfo(at, name, parent, (int)size, List.copyOf(list),
            List.of("32-bit hkClass/hkClassMember relational layout", "bounded unique member names and offsets",
                "mapped parent, class, enum and member pointers"));
    }

    private static boolean validParent(ClassInfo c, Map<Long, ClassInfo> all, Set<Long> visited) {
        if (!visited.add(c.address)) return false;
        if (c.parent == 0) return true;
        ClassInfo parent = all.get(c.parent);
        return parent != null && parent.objectSize <= c.objectSize && validParent(parent, all, visited);
    }

    public static String snake(String name) {
        return name.replace("::", "_").replaceAll("([A-Z]+)([A-Z][a-z])", "$1_$2")
            .replaceAll("([a-z0-9])([A-Z])", "$1_$2").toLowerCase(Locale.ROOT);
    }
}
