package xenon360.xex;

import java.io.IOException;
import java.util.Arrays;

/**
 * LZX decoder for Xbox 360 XEX2 NORMAL-compressed images.
 *
 * <p>Adapted to Java from the MIT-licensed pure-Python XEX2 LZX decoder in
 * sp00nznet/360tools (tools/lzx_decompress.py), with additional bounds checks
 * and a fixed 0x8000-byte LZX frame size matching the Xbox/Xenia decode path.
 */
final class XenonLzxDecoder {
    private static final int NUM_CHARS = 256;
    private static final int MIN_MATCH = 2;
    private static final int NUM_PRIMARY_LENGTHS = 7;
    private static final int SECONDARY_NUM_ELEMENTS = 249;

    private static final int PRETREE_NUM = 20;
    private static final int PRETREE_TABLE_BITS = 6;
    private static final int PRETREE_MAX_SYMBOLS = 20;
    private static final int PRETREE_MAX_CODEWORD = 16;

    private static final int MAINTREE_TABLE_BITS = 11;
    private static final int MAINTREE_MAX_SYMBOLS = NUM_CHARS + (51 << 3);
    private static final int MAINTREE_MAX_CODEWORD = 16;

    private static final int LENTREE_TABLE_BITS = 10;
    private static final int LENTREE_MAX_SYMBOLS = SECONDARY_NUM_ELEMENTS;
    private static final int LENTREE_MAX_CODEWORD = 16;

    private static final int ALIGNTREE_TABLE_BITS = 7;
    private static final int ALIGNTREE_MAX_SYMBOLS = 8;
    private static final int ALIGNTREE_MAX_CODEWORD = 8;

    private static final int LENTABLE_SAFETY = 64;
    private static final int BLOCKTYPE_VERBATIM = 1;
    private static final int BLOCKTYPE_ALIGNED = 2;
    private static final int BLOCKTYPE_UNCOMPRESSED = 3;
    private static final int FRAME_SIZE = 0x8000;

    private static final int[] POSITION_SLOTS = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        30, 32, 34, 36, 38, 42, 50 };
    private static final int[] POSITION_BASE = {
        0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192,
        256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
        12288, 16384, 24576, 32768, 49152, 65536, 98304, 131072, 196608,
        262144, 393216, 524288, 655360, 786432, 917504, 1048576, 1179648,
        1310720, 1441792, 1572864, 1703936, 1835008, 1966080, 2097152
    };
    private static final int[] EXTRA_BITS = {
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
        7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
        15, 15, 16, 16, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
        17, 17, 17, 17
    };

    private final int windowBits;
    private final int windowSize;
    private final int numPositionSlots;
    private final int mainElements;

    private final int[] pretreeTable = new int[(1 << PRETREE_TABLE_BITS) + (PRETREE_MAX_SYMBOLS << 1)];
    private final int[] pretreeLengths = new int[PRETREE_MAX_SYMBOLS + LENTABLE_SAFETY];
    private final int[] mainTable = new int[(1 << MAINTREE_TABLE_BITS) + (MAINTREE_MAX_SYMBOLS << 1)];
    private final int[] mainLengths = new int[MAINTREE_MAX_SYMBOLS + LENTABLE_SAFETY];
    private final int[] lengthTable = new int[(1 << LENTREE_TABLE_BITS) + (LENTREE_MAX_SYMBOLS << 1)];
    private final int[] lengthLengths = new int[LENTREE_MAX_SYMBOLS + LENTABLE_SAFETY];
    private final int[] alignedTable = new int[(1 << ALIGNTREE_TABLE_BITS) + (ALIGNTREE_MAX_SYMBOLS << 1)];
    private final int[] alignedLengths = new int[ALIGNTREE_MAX_SYMBOLS + LENTABLE_SAFETY];

    private int blockRemaining;
    private int blockLength;
    private int blockType;
    private int r0 = 1, r1 = 1, r2 = 1;
    private boolean headerRead;
    private int intelFileSize;
    private boolean intelStarted;

    XenonLzxDecoder(int windowSize) throws IOException {
        if (windowSize < (1 << 15) || windowSize > (1 << 21) || (windowSize & (windowSize - 1)) != 0)
            throw bad("LZX window size must be a power of two from 32 KiB through 2 MiB");
        this.windowBits = Integer.numberOfTrailingZeros(windowSize);
        this.windowSize = windowSize;
        this.numPositionSlots = POSITION_SLOTS[windowBits];
        this.mainElements = NUM_CHARS + (numPositionSlots << 3);
    }

    byte[] decompress(byte[] data, int outputSize) throws IOException {
        return decompress(data, outputSize, null);
    }

    byte[] decompress(byte[] data, int outputSize, byte[] referenceData) throws IOException {
        if (outputSize < 0) throw bad("Negative LZX output size");
        if (referenceData != null && referenceData.length > windowSize)
            throw bad("LZX reference data exceeds window");
        byte[] referenceWindow = null;
        if (referenceData != null) {
            referenceWindow = new byte[windowSize];
            System.arraycopy(referenceData, 0, referenceWindow,
                windowSize - referenceData.length, referenceData.length);
        }
        byte[] output = new byte[outputSize];
        boolean[] e8Frames = new boolean[(outputSize + FRAME_SIZE - 1) / FRAME_SIZE];
        BitBuffer bits = new BitBuffer(data);
        int outPos = 0;
        int windowPos = 0;
        int framePos = 0;

        if (!headerRead) {
            if (bits.readBits(1) != 0) {
                int hi = bits.readBits(16);
                int lo = bits.readBits(16);
                intelFileSize = hi << 16 | lo;
            }
            intelStarted = false;
            headerRead = true;
        }

        while (outPos < outputSize) {
            int frameOut = Math.min(FRAME_SIZE, outputSize - outPos);
            int bytesTodo = framePos + frameOut - windowPos;
            if (bytesTodo < 0) bytesTodo = 0;

            while (bytesTodo > 0) {
                if (blockRemaining == 0) readBlockHeader(bits);
                int thisRun = blockRemaining;
                if (thisRun > bytesTodo) thisRun = bytesTodo;
                bytesTodo -= thisRun;
                blockRemaining -= thisRun;
                if (thisRun <= 0) continue;

                if (blockType == BLOCKTYPE_UNCOMPRESSED) {
                    bits.requireRaw(thisRun);
                    for (int i = 0; i < thisRun; i++) {
                        output[windowPos++] = (byte)bits.readRawByte();
                    }
                }
                else {
                    while (thisRun > 0) {
                        int main = readHuffSym(mainTable, mainLengths, MAINTREE_MAX_SYMBOLS,
                            MAINTREE_TABLE_BITS, bits, MAINTREE_MAX_CODEWORD);
                        if (main < NUM_CHARS) {
                            if (windowPos >= output.length) throw bad("LZX literal exceeds output size");
                            output[windowPos++] = (byte)main;
                            thisRun--;
                            continue;
                        }

                        main -= NUM_CHARS;
                        int matchLength = main & NUM_PRIMARY_LENGTHS;
                        if (matchLength == NUM_PRIMARY_LENGTHS) {
                            matchLength += readHuffSym(lengthTable, lengthLengths, LENTREE_MAX_SYMBOLS,
                                LENTREE_TABLE_BITS, bits, LENTREE_MAX_CODEWORD);
                        }
                        matchLength += MIN_MATCH;

                        int slot = main >>> 3;
                        int matchOffset;
                        if (slot > 2) {
                            if (slot >= EXTRA_BITS.length || slot >= POSITION_BASE.length)
                                throw bad("LZX position slot outside table");
                            int extra = EXTRA_BITS[slot];
                            int verbatim;
                            int aligned = 0;
                            if (blockType == BLOCKTYPE_ALIGNED && extra >= 3) {
                                verbatim = bits.readBits(extra - 3) << 3;
                                aligned = readHuffSym(alignedTable, alignedLengths, ALIGNTREE_MAX_SYMBOLS,
                                    ALIGNTREE_TABLE_BITS, bits, ALIGNTREE_MAX_CODEWORD);
                            }
                            else {
                                verbatim = bits.readBits(extra);
                            }
                            matchOffset = POSITION_BASE[slot] + verbatim + aligned - 2;
                            r2 = r1; r1 = r0; r0 = matchOffset;
                        }
                        else if (slot == 0) {
                            matchOffset = r0;
                        }
                        else if (slot == 1) {
                            matchOffset = r1; r1 = r0; r0 = matchOffset;
                        }
                        else {
                            matchOffset = r2; r2 = r0; r0 = matchOffset;
                        }

                        if (matchOffset <= 0 || matchOffset > windowSize)
                            throw bad("LZX match offset exceeds window");
                        thisRun -= matchLength;
                        copyMatch(output, referenceWindow, windowPos, matchOffset, matchLength);
                        windowPos += matchLength;
                    }
                    if (thisRun < 0) blockRemaining += thisRun;
                }
            }

            if (bits.bitsLeft > 0) bits.ensureBits(16);
            if ((bits.bitsLeft & 15) != 0) bits.removeBits(bits.bitsLeft & 15);

            if (framePos != outPos && (framePos < 0 || framePos + frameOut > output.length))
                throw bad("LZX frame accounting outside output");
            e8Frames[framePos / FRAME_SIZE] = intelStarted && intelFileSize != 0 && frameOut > 10;
            outPos += frameOut;
            framePos += frameOut;
        }

        if (windowPos < outputSize) throw bad("LZX stream produced too little output");
        byte[] translated = output.clone();
        for (int frame = 0; frame < e8Frames.length; frame++) {
            if (!e8Frames[frame]) continue;
            int start = frame * FRAME_SIZE;
            int length = Math.min(FRAME_SIZE, translated.length - start);
            e8DecodeFrame(translated, start, length);
        }
        return translated;
    }

    private void copyMatch(byte[] output, byte[] referenceWindow, int outPos,
            int offset, int length) throws IOException {
        if ((long)outPos + length > output.length + 257L)
            throw bad("LZX match exceeds bounded output");
        for (int i = 0; i < length; i++) {
            int dest = outPos + i;
            if (dest >= output.length) break;
            int source = dest - offset;
            if (source >= 0) {
                output[dest] = output[source];
            }
            else {
                if (referenceWindow == null || source < -windowSize)
                    throw bad("LZX match offset points before start of stream");
                output[dest] = referenceWindow[windowSize + source];
            }
        }
    }

    private void readBlockHeader(BitBuffer bits) throws IOException {
        if (blockType == BLOCKTYPE_UNCOMPRESSED) {
            if ((blockLength & 1) != 0) bits.skipRawByte();
            bits.resetBits();
        }

        blockType = bits.readBits(3);
        blockLength = bits.readBits(24);
        if (blockLength <= 0) throw bad("Zero-length LZX block");
        blockRemaining = blockLength;

        if (blockType == BLOCKTYPE_ALIGNED) {
            for (int i = 0; i < ALIGNTREE_MAX_SYMBOLS; i++) alignedLengths[i] = bits.readBits(3);
            makeDecodeTable(ALIGNTREE_MAX_SYMBOLS, ALIGNTREE_TABLE_BITS, alignedLengths, alignedTable);
        }

        if (blockType == BLOCKTYPE_VERBATIM || blockType == BLOCKTYPE_ALIGNED) {
            readLengths(mainLengths, 0, NUM_CHARS, bits);
            readLengths(mainLengths, NUM_CHARS, mainElements, bits);
            makeDecodeTable(MAINTREE_MAX_SYMBOLS, MAINTREE_TABLE_BITS, mainLengths, mainTable);
            if (mainLengths[0xE8] != 0) intelStarted = true;
            readLengths(lengthLengths, 0, SECONDARY_NUM_ELEMENTS, bits);
            makeDecodeTable(LENTREE_MAX_SYMBOLS, LENTREE_TABLE_BITS, lengthLengths, lengthTable);
        }
        else if (blockType == BLOCKTYPE_UNCOMPRESSED) {
            intelStarted = true;
            bits.ensureBits(16);
            if (bits.bitsLeft > 16) bits.rewindRawWord();
            bits.resetBits();
            r0 = bits.readRawLe32();
            r1 = bits.readRawLe32();
            r2 = bits.readRawLe32();
            if (r0 <= 0 || r1 <= 0 || r2 <= 0 || r0 > windowSize || r1 > windowSize || r2 > windowSize)
                throw bad("Invalid LZX repeated offset in uncompressed block");
        }
        else {
            throw bad("Invalid LZX block type " + blockType);
        }
    }

    private void readLengths(int[] lengths, int first, int last, BitBuffer bits) throws IOException {
        for (int i = 0; i < PRETREE_NUM; i++) pretreeLengths[i] = bits.readBits(4);
        makeDecodeTable(PRETREE_MAX_SYMBOLS, PRETREE_TABLE_BITS, pretreeLengths, pretreeTable);
        int x = first;
        while (x < last) {
            int z = readHuffSym(pretreeTable, pretreeLengths, PRETREE_MAX_SYMBOLS,
                PRETREE_TABLE_BITS, bits, PRETREE_MAX_CODEWORD);
            if (z == 17) {
                int run = bits.readBits(4) + 4;
                if (run > last - x) throw bad("LZX zero-run exceeds code-length table");
                Arrays.fill(lengths, x, x + run, 0); x += run;
            }
            else if (z == 18) {
                int run = bits.readBits(5) + 20;
                if (run > last - x) throw bad("LZX long zero-run exceeds code-length table");
                Arrays.fill(lengths, x, x + run, 0); x += run;
            }
            else if (z == 19) {
                int run = bits.readBits(1) + 4;
                if (run > last - x) throw bad("LZX repeated length-run exceeds code-length table");
                int delta = readHuffSym(pretreeTable, pretreeLengths, PRETREE_MAX_SYMBOLS,
                    PRETREE_TABLE_BITS, bits, PRETREE_MAX_CODEWORD);
                int value = (lengths[x] + 17 - delta) % 17;
                Arrays.fill(lengths, x, x + run, value); x += run;
            }
            else {
                lengths[x] = (lengths[x] + 17 - z) % 17;
                x++;
            }
        }
    }

    private static void makeDecodeTable(int nsyms, int nbits, int[] lengths, int[] table) throws IOException {
        Arrays.fill(table, 0);
        int pos = 0;
        int tableMask = 1 << nbits;
        int bitMask = tableMask >>> 1;
        int nextSymbol = bitMask;

        for (int bitNum = 1; bitNum <= nbits; bitNum++) {
            for (int sym = 0; sym < nsyms; sym++) {
                if (lengths[sym] != bitNum) continue;
                int leaf = pos;
                pos += bitMask;
                if (pos > tableMask) throw bad("Oversubscribed LZX Huffman table");
                Arrays.fill(table, leaf, leaf + bitMask, sym);
            }
            bitMask >>>= 1;
        }
        if (pos == tableMask) return;
        Arrays.fill(table, pos, tableMask, 0);

        pos <<= 16;
        tableMask <<= 16;
        bitMask = 1 << 15;
        for (int bitNum = nbits + 1; bitNum <= 16; bitNum++) {
            for (int sym = 0; sym < nsyms; sym++) {
                if (lengths[sym] != bitNum) continue;
                int leaf = pos >>> 16;
                for (int depth = 0; depth < bitNum - nbits; depth++) {
                    if (leaf < 0 || leaf >= table.length) throw bad("LZX Huffman tree index outside table");
                    if (table[leaf] == 0) {
                        int left = nextSymbol << 1;
                        if (left + 1 >= table.length) throw bad("LZX Huffman tree exceeds table capacity");
                        table[left] = table[left + 1] = 0;
                        table[leaf] = nextSymbol++;
                    }
                    leaf = table[leaf] << 1;
                    if (((pos >>> (15 - depth)) & 1) != 0) leaf++;
                }
                if (leaf < 0 || leaf >= table.length) throw bad("LZX Huffman leaf outside table");
                table[leaf] = sym;
                pos += bitMask;
                if (pos > tableMask) throw bad("Oversubscribed long LZX Huffman table");
            }
            bitMask >>>= 1;
        }
        if (pos == tableMask) return;
        for (int sym = 0; sym < nsyms; sym++) if (lengths[sym] != 0)
            throw bad("Incomplete non-empty LZX Huffman table");
    }

    private static int readHuffSym(int[] table, int[] lengths, int nsyms, int nbits,
            BitBuffer bits, int maxCodeword) throws IOException {
        bits.ensureBits(maxCodeword);
        int direct = bits.peekBits(nbits);
        if (direct < 0 || direct >= table.length) throw bad("LZX Huffman direct index outside table");
        int symbol = table[direct];
        if (symbol >= nsyms) {
            int bitPos = bits.bitsLeft - nbits - 1;
            while (symbol >= nsyms) {
                long index = (long)symbol << 1;
                if (bitPos < 0) throw bad("Truncated long LZX Huffman code");
                if (((bits.buffer >>> bitPos) & 1) != 0) index++;
                bitPos--;
                if (index < 0 || index >= table.length) throw bad("LZX Huffman tree walk outside table");
                symbol = table[(int)index];
            }
        }
        if (symbol < 0 || symbol >= lengths.length || lengths[symbol] <= 0)
            throw bad("Invalid LZX Huffman symbol");
        bits.removeBits(lengths[symbol]);
        return symbol;
    }

    private void e8DecodeFrame(byte[] data, int start, int size) {
        int i = 0;
        while (i < size - 10) {
            int at = start + i;
            if ((data[at] & 0xFF) != 0xE8) { i++; continue; }
            int curPos = start + i;
            int abs = (data[at + 1] & 255) | (data[at + 2] & 255) << 8
                | (data[at + 3] & 255) << 16 | data[at + 4] << 24;
            if (abs >= -curPos && abs < intelFileSize) {
                int rel = abs >= 0 ? abs - curPos : abs + intelFileSize;
                data[at + 1] = (byte)rel;
                data[at + 2] = (byte)(rel >>> 8);
                data[at + 3] = (byte)(rel >>> 16);
                data[at + 4] = (byte)(rel >>> 24);
            }
            i += 5;
        }
    }

    private static IOException bad(String message) { return new IOException(message); }

    static final class BitBuffer {
        final byte[] data;
        long buffer;
        int bitsLeft;
        int pos;
        int eofPaddingBytes;

        BitBuffer(byte[] data) { this.data = data; }

        private int readBitstreamByte() throws IOException {
            if (pos < data.length) return data[pos++] & 255;
            // libmspack intentionally supplies exactly two zero bytes at physical EOF.
            // Huffman lookup may ENSURE_BITS(16) for lookahead even when the decoded
            // symbol consumes fewer remaining bits. More than two bytes is a real
            // truncated stream and must still fail.
            if (eofPaddingBytes < 2) {
                eofPaddingBytes++;
                return 0;
            }
            throw bad("Truncated LZX bitstream");
        }

        void ensureBits(int n) throws IOException {
            while (bitsLeft < n) {
                int lo = readBitstreamByte();
                int hi = readBitstreamByte();
                buffer = buffer << 16 | (hi << 8 | lo);
                bitsLeft += 16;
            }
        }

        int peekBits(int n) throws IOException {
            if (n == 0) return 0;
            ensureBits(n);
            long mask = (1L << n) - 1;
            return (int)(buffer >>> (bitsLeft - n) & mask);
        }

        int readBits(int n) throws IOException {
            int value = peekBits(n);
            removeBits(n);
            return value;
        }

        void removeBits(int n) throws IOException {
            if (n < 0 || n > bitsLeft) throw bad("Invalid LZX bit removal");
            bitsLeft -= n;
            if (bitsLeft == 0) buffer = 0;
            else buffer &= (1L << bitsLeft) - 1;
        }

        void resetBits() { buffer = 0; bitsLeft = 0; }
        void rewindRawWord() throws IOException {
            if (pos < 2) throw bad("Invalid LZX raw-word rewind");
            pos -= 2;
        }
        void skipRawByte() throws IOException {
            if (pos >= data.length) throw bad("Truncated LZX uncompressed padding");
            pos++;
        }
        void requireRaw(int n) throws IOException {
            if (n < 0 || pos > data.length || n > data.length - pos) throw bad("Truncated LZX uncompressed block");
        }
        int readRawByte() throws IOException {
            requireRaw(1); return data[pos++] & 255;
        }
        int readRawLe32() throws IOException {
            requireRaw(4);
            int v = (data[pos] & 255) | (data[pos + 1] & 255) << 8
                | (data[pos + 2] & 255) << 16 | data[pos + 3] << 24;
            pos += 4; return v;
        }
    }
}
