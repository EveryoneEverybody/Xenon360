package xenon360.analysis;

import java.nio.charset.StandardCharsets;
import java.util.*;

/** Bounded, immutable view of mapped bytes. Addresses are never file offsets. */
public final class BinaryImage {
    public record Segment(long address, byte[] bytes, boolean executable) {
        public long end() { return address + bytes.length; }
    }
    public record Mapping(long address, long size) {}
    public final List<Segment> segments;
    public final List<Mapping> mappings;
    public final int pointerSize;
    public final boolean bigEndian;
    public final boolean powerPc;

    public BinaryImage(List<Segment> segments, int pointerSize, boolean bigEndian, boolean powerPc) {
        this(segments, segments.stream().map(s -> new Mapping(s.address(),s.bytes().length)).toList(),
            pointerSize,bigEndian,powerPc);
    }
    public BinaryImage(List<Segment> segments, List<Mapping> mappings, int pointerSize, boolean bigEndian, boolean powerPc) {
        if (pointerSize != 4 && pointerSize != 8) throw new IllegalArgumentException("Pointer width");
        this.segments = segments.stream().sorted(Comparator.comparingLong(Segment::address)).toList();
        this.mappings = List.copyOf(mappings);
        this.pointerSize = pointerSize;
        this.bigEndian = bigEndian;
        this.powerPc = powerPc;
        long end = -1;
        for (Segment s : this.segments) {
            if (s.address < 0 || s.end() < s.address || s.address < end) {
                throw new IllegalArgumentException("Overlapping or overflowing mapped segments");
            }
            end = s.end();
        }
    }
    public boolean mapped(long at, int size) {
        if(at<0 || size<0 || at>Long.MAX_VALUE-size)return false;
        return mappings.stream().anyMatch(m->m.address()>=0 && m.size()>=0 &&
            m.address()<=Long.MAX_VALUE-m.size() && at>=m.address() && at+size<=m.address()+m.size());
    }
    public Segment segment(long address, int length) {
        if (length < 0 || address < 0 || address > Long.MAX_VALUE - length) return null;
        for (Segment s : segments) {
            if (s.address > address) return null;
            if (address >= s.address && address + length <= s.end()) return s;
        }
        return null;
    }
    public boolean executable(long address) {
        Segment s = segment(address, powerPc ? 4 : 1);
        return s != null && s.executable && (!powerPc || (address & 3) == 0);
    }
    public long unsigned(long address, int size) {
        Segment s = segment(address, size);
        if (s == null) return -1;
        int offset = (int)(address - s.address);
        long value = 0;
        for (int i = 0; i < size; i++) {
            value = (value << 8) | (s.bytes[offset + (bigEndian ? i : size - 1 - i)] & 255L);
        }
        return value;
    }
    public long pointer(long address) { return unsigned(address, pointerSize); }
    public String string(long address, int max) {
        Segment s = segment(address, 1);
        if (s == null || s.executable) return null;
        int start = (int)(address - s.address);
        for (int i = start; i < s.bytes.length && i - start <= max; i++) {
            int c = s.bytes[i] & 255;
            if (c == 0) return new String(s.bytes, start, i - start, StandardCharsets.US_ASCII);
            if (c < 32 || c > 126) return null;
        }
        return null;
    }
    public static String address(long value) { return "0x" + Long.toHexString(value); }
}
