package xenon360;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.*;
import java.util.*;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.opinion.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.model.DomainObject;
import ghidra.framework.options.Options;
import ghidra.program.model.address.*;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import xenon360.xex.XexImage;
import xenon360.xex.XenonXexIntegrity;
import xenon360.xex.XexPatch;
import xenon360.xex.XenonOrdinalResolver;

/** Xbox 360 XEX/XEXP loader for the Xenon VMX128 language. Ghidra 12.1 API. */
public final class XenonXexLoader extends AbstractProgramWrapperLoader {
    public static final String FORMAT_NAME = "Xenon360 XEX";
    public static final String LANGUAGE = "PowerPC:BE:64:Xenon-VMX128-32addr";
    public static final String BASE_XEX_OPTION = "Base XEX path (required for XEXP)";
    public static final String BASE_XEX_ARG = "-loader-base-xex";
    public static final String SYMBOL_OPTION = "PDB/XDB path (optional)";
    public static final String SYMBOL_ARG = "-loader-symbol-file";
    public static final String SYMBOL_MODE_OPTION = "PDB/XDB processing mode (public-symbols|all)";
    public static final String SYMBOL_MODE_ARG = "-loader-symbol-mode";

    @Override public String getName() { return FORMAT_NAME; }
    @Override public int getTierPriority() { return 10; }
    @Override public boolean supportsLoadIntoProgram(Program program) { return false; }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        if (provider.length() < 24 || !XexImage.recognizes(provider.readBytes(0, 4))) return List.of();
        // Recognize unsupported XEX2 variants too, so import gives a precise error rather than Raw Binary.
        return List.of(new LoadSpec(this, 0, new LanguageCompilerSpecPair(LANGUAGE, "default"), true));
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean loadIntoProgram, boolean mirrorFsLayout) {
        List<Option> options = new ArrayList<>();
        try {
            if (provider.length() >= 8 && XexPatch.isDeltaPatch(provider.readBytes(0, 8))) {
                options.add(new XenonFilePathOption(
                    BASE_XEX_OPTION, BASE_XEX_ARG, "Choose source XEX",
                    "Select", "Xbox 360 XEX files", "xex"));
            }
        }
        catch (IOException ignored) { }
        options.add(new XenonFilePathOption(
            SYMBOL_OPTION, SYMBOL_ARG, "Choose matching PDB or XDB",
            "Select", "Xbox debug symbols", "pdb", "xdb"));
        options.add(new XenonChoiceOption(
            SYMBOL_MODE_OPTION, "public-symbols", SYMBOL_MODE_ARG,
            "public-symbols", "all"));
        return options;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program) {
        try {
            if (provider.length() >= 8 && XexPatch.isDeltaPatch(provider.readBytes(0, 8))) {
                String base = stringOption(options, BASE_XEX_OPTION);
                if (base == null || base.isBlank()) return "Base XEX path is required for XEXP imports";
                Path path = Path.of(base);
                if (!Files.isRegularFile(path)) return "Base XEX path is not a file: " + base;
                if (Files.size(path) > XexImage.MAX_FILE_BYTES)
                    return "Base XEX exceeds 256 MiB input limit";
            }
            String symbolMode = stringOption(options, SYMBOL_MODE_OPTION);
            if (symbolMode == null || symbolMode.isBlank()) symbolMode = "public-symbols";
            if (!symbolMode.equals("public-symbols") && !symbolMode.equals("all"))
                return "PDB/XDB processing mode must be public-symbols or all";
            String symbol = stringOption(options, SYMBOL_OPTION);
            if (symbol != null && !symbol.isBlank()) {
                Path path = Path.of(symbol);
                if (!Files.isRegularFile(path)) return "PDB/XDB path is not a file: " + symbol;
                long size = Files.size(path);
                if (size <= 0 || size > XenonPdbSupport.MAX_SYMBOL_BYTES)
                    return "PDB/XDB exceeds 512 MiB limit or is empty";
                String name = path.getFileName().toString().toLowerCase(Locale.ROOT);
                if (!name.endsWith(".pdb") && !name.endsWith(".xdb"))
                    return "Symbol file must end in .pdb or .xdb";
            }
        }
        catch (Exception ex) {
            return "Invalid loader option: " + ex.getMessage();
        }
        return super.validateOptions(provider, loadSpec, options, program);
    }

    @Override
    protected void load(Program program, ImporterSettings settings) throws IOException, CancelledException {
        TaskMonitor monitor = settings.monitor();
        MessageLog log = settings.log();
        if (!program.getLanguageID().toString().equals(LANGUAGE)) throw new IOException("Wrong Xenon language");
        if (program.getMemory().getBlocks().length != 0)
            throw new IOException("Xenon360 loads fresh programs only; use a separate import");
        if (settings.provider().length() > XexImage.MAX_FILE_BYTES)
            throw new IOException("XEX exceeds 256 MiB prototype input limit");
        monitor.checkCancelled();
        byte[] source = settings.provider().readBytes(0, settings.provider().length());
        XexPatch.Applied appliedPatch = null;
        XexImage x;
        String sourceHash;
        String effectiveKeyKind;
        String baseHash = null;
        if (XexPatch.isDeltaPatch(source)) {
            String baseOption = stringOption(settings.options(), BASE_XEX_OPTION);
            if (baseOption == null || baseOption.isBlank())
                throw new IOException("Base XEX path is required for XEXP imports");
            Path basePath = Path.of(baseOption);
            if (!Files.isRegularFile(basePath))
                throw new IOException("Base XEX path is not a file: " + baseOption);
            long baseLength = Files.size(basePath);
            if (baseLength > XexImage.MAX_FILE_BYTES)
                throw new IOException("Base XEX exceeds 256 MiB input limit");
            monitor.setMessage("Xenon360: applying XEXP delta patch");
            byte[] baseFile = Files.readAllBytes(basePath);
            baseHash = XexImage.sha256(baseFile);
            appliedPatch = XexPatch.apply(baseFile, source);
            x = appliedPatch.image();
            sourceHash = appliedPatch.patch().sourceSha256();
            effectiveKeyKind = appliedPatch.keyKind();
        }
        else {
            monitor.setMessage("Xenon360: reconstructing XEX2 image");
            x = XexImage.parse(source);
            sourceHash = x.sourceSha256;
            effectiveKeyKind = x.keyKind;
        }
        String symbolOption = stringOption(settings.options(), SYMBOL_OPTION);
        String symbolMode = stringOption(settings.options(), SYMBOL_MODE_OPTION);
        if (symbolMode == null || symbolMode.isBlank()) symbolMode = "public-symbols";
        Path symbolPath = null;
        XenonPdbSupport.Info symbolInfo = null;
        if (symbolOption != null && !symbolOption.isBlank()) {
            symbolPath = Path.of(symbolOption);
            monitor.setMessage("Xenon360: validating PDB/XDB identity");
            symbolInfo = XenonPdbSupport.validate(symbolPath, x.codeView, monitor);
            monitor.checkCancelled();
        }

        monitor.checkCancelled();
        try {
            AddressSpace space = program.getAddressFactory().getDefaultAddressSpace();
            program.setImageBase(space.getAddress(x.imageBase), true);
            Memory memory = program.getMemory();
            Options info = program.getOptions("Xenon360");
            info.setString("Loader version", XexImage.VERSION);
            info.setString("Container magic", x.containerMagic);
            info.setString("Source SHA-256", sourceHash);
            info.setString("Reconstructed image SHA-256", XexImage.sha256(x.image));
            info.setString("Key kind", effectiveKeyKind);
            info.setInt("Compression type", x.compression);
            if (appliedPatch != null) {
                info.setBoolean("XEXP delta applied", true);
                info.setString("Base XEX SHA-256", baseHash);
                info.setString("Normalized patched XEX SHA-256",
                    XexImage.sha256(appliedPatch.normalizedXex()));
                info.setString("XEXP source version", appliedPatch.patch().sourceVersionHex());
                info.setString("XEXP target version", appliedPatch.patch().targetVersionHex());
                info.setInt("XEXP target header encryption type", appliedPatch.targetEncryption());
                info.setInt("XEXP target header compression type", appliedPatch.targetCompression());
                info.setInt("XEXP patch block count", appliedPatch.payloadInfo().blockCount());
                info.setInt("XEXP delta record count", appliedPatch.payloadInfo().recordCount());
                info.setInt("XEXP zero records", appliedPatch.payloadInfo().zeroRecords());
                info.setInt("XEXP copy records", appliedPatch.payloadInfo().copyRecords());
                info.setInt("XEXP LZX-delta records", appliedPatch.payloadInfo().lzxDeltaRecords());
            }
            if (x.compression == 2) {
                info.setInt("NORMAL LZX window size", x.normalWindowSize);
                info.setInt("NORMAL block count", x.normalBlockCount);
                info.setInt("NORMAL LZX stream bytes", x.normalLzxBytes);
                info.setInt("NORMAL trailing payload bytes", x.normalTrailingBytes);
            }
            info.setLong("XEX image size", x.image.length);
            info.setLong("PE preferred ImageBase", x.peImageBase);
            info.setLong("PE SizeOfImage", x.peSizeOfImage);
            info.setString("Section tail policy", "preserve available prefix; explicitly synthetic zero tail");
            info.setString("Import naming", "pinned Xenia/SDK export name when known; library+ordinal fallback for unknown or generation-conflicting ordinals");
            info.setString("Import ordinal source", XenonOrdinalResolver.SOURCE_ID);
            info.setString("Signature verification", "not performed");
            if (x.codeView != null) {
                info.setString("CodeView signature", x.codeView.signature());
                info.setString("CodeView GUID", x.codeView.guid());
                info.setLong("CodeView age", x.codeView.age());
                info.setString("CodeView PDB path", x.codeView.path());
            }
            else {
                info.setString("CodeView signature", "not-present");
            }
            if (symbolInfo != null) {
                info.setString("Symbol kind", symbolInfo.kind());
                info.setString("Symbol SHA-256", symbolInfo.sha256());
                info.setString("Symbol GUID", symbolInfo.guid());
                info.setInt("Symbol age", symbolInfo.age());
                info.setString("Symbol target processor", symbolInfo.processor());
                info.setString("Symbol engine", "Ghidra 12.1 PDB Universal");
                info.setString("Symbol processing mode", symbolMode);
                info.setString("Symbol file path", symbolPath.toAbsolutePath().normalize().toString());
                info.setBoolean("Symbol identity verified", true);
                info.setBoolean("Symbol main application", false);
            }
            AddressSet executable = new AddressSet();
            for (XexImage.Section section : x.sections) {
                monitor.checkCancelled();
                if (section.size() == 0) continue;
                monitor.setMessage("Xenon360: mapping " + section.name());
                byte[] content = x.sectionBytes(section);
                Address start = space.getAddress(x.imageBase + section.rva());
                MemoryBlock block = memory.createInitializedBlock(section.name(), start,
                    new ByteArrayInputStream(content), content.length, monitor, false);
                block.setRead(section.read()); block.setWrite(section.write()); block.setExecute(section.execute());
                block.setComment("Xenon360 " + x.containerMagic
                    + "; PE section name=" + section.peName()
                    + "; reconstructed image bytes=" + section.availableBytes()
                    + "; synthetic zero tail=" + section.syntheticTailBytes());
                if (section.execute() && section.availableBytes() != 0)
                    executable.addRange(start, start.addNoWrap(section.availableBytes() - 1L));
                info.setString("Section " + section.name() + " SHA-256", XexImage.sha256(content));
                info.setLong("Section " + section.name() + " synthetic tail", section.syntheticTailBytes());
                log.appendMsg("section=" + section.name() + ";start=" + start + ";size=" + content.length
                    + ";synthetic_tail=" + section.syntheticTailBytes());
            }
            for (String warning : x.warnings) log.appendMsg("WARNING: " + warning);
            if (appliedPatch == null) {
                XenonXexIntegrity.Result integrity = XenonXexIntegrity.verify(source, x);
                info.setString("Signature verification", integrity.signature());
                info.setString("Header hash verification", integrity.headerHash());
                info.setString("Image hash verification", integrity.imageHash());
                info.setString("Import hash verification", integrity.importHash());
                log.appendMsg("integrity_signature=" + integrity.signature()
                    + ";integrity_header_hash=" + integrity.headerHash()
                    + ";integrity_image_hash=" + integrity.imageHash()
                    + ";integrity_import_hash=" + integrity.importHash());
                if (!integrity.allApplicableHashesValid())
                    log.appendMsg("WARNING: one or more applicable XEX integrity hashes are invalid");
            }
            else {
                info.setString("Signature verification", "not-applicable-patched-target");
                info.setString("Header hash verification", "not-applicable-patched-target");
                info.setString("Image hash verification", "not-applicable-patched-target");
                info.setString("Import hash verification", "not-applicable-patched-target");
            }
            importSymbols(program, x, monitor, log, info, executable);

            AddressSet seeds = new AddressSet();
            if (x.entryPoint != 0) {
                Address entry = space.getAddress(x.entryPoint);
                program.getSymbolTable().addExternalEntryPoint(entry);
                program.getSymbolTable().createLabel(entry, "xex_entry", SourceType.IMPORTED);
                seeds.add(entry);
            }
            int invalid = 0, duplicate = 0;
            for (XexImage.PdataRecord record : x.pdata) {
                monitor.checkCancelled();
                if ((record.entry() & 3) != 0 || !x.executable(record.entry(), 4)) { invalid++; continue; }
                Address at = space.getAddress(record.entry());
                if (seeds.contains(at)) duplicate++;
                seeds.add(at);
            }
            info.setInt("Pdata records", x.pdata.size());
            info.setInt("Pdata invalid or padding records", invalid);
            info.setInt("Pdata duplicate seeds", duplicate);
            info.setLong("Function seed count including entry", seeds.getNumAddresses());
            // Import records are metadata, not patched runtime instructions. Do not decode those words.
            AddressSet decodeSeeds = seeds.intersect(executable);
            monitor.setMessage("Xenon360: disassembling entry and .pdata seeds");
            DisassembleCommand disassemble = new DisassembleCommand(decodeSeeds, executable, true);
            disassemble.enableCodeAnalysis(false);
            boolean disassemblyComplete = disassemble.applyTo(program, monitor);
            monitor.checkCancelled();
            if (!disassemblyComplete) log.appendMsg("Seed disassembly diagnostic: " + disassemble.getStatusMsg());

            monitor.setMessage("Xenon360: creating .pdata function seeds");
            CreateFunctionCmd functions = new CreateFunctionCmd(seeds);
            boolean functionsComplete = functions.applyTo(program, monitor);
            monitor.checkCancelled();
            long missing = 0;
            AddressIterator it = seeds.getAddresses(true);
            while (it.hasNext()) {
                monitor.checkCancelled();
                if (program.getFunctionManager().getFunctionAt(it.next()) == null) missing++;
            }
            info.setLong("Missing function seeds before Auto Analysis", missing);
            if (!functionsComplete) log.appendMsg("Function seed diagnostic: " + functions.getStatusMsg());

            monitor.setMessage("Xenon360: modeling compiler helper families");
            XenonCompilerHelperBootstrap.Result helperBootstrap =
                XenonCompilerHelperBootstrap.apply(program, monitor);
            info.setInt("Compiler helper families", helperBootstrap.families());
            info.setInt("Compiler helper entries modeled before Auto Analysis",
                helperBootstrap.entries());
            info.setInt("Compiler helper functions created during bootstrap",
                helperBootstrap.createdFunctions());
            log.appendMsg("compiler_helper_bootstrap_families=" + helperBootstrap.families()
                + ";entries=" + helperBootstrap.entries()
                + ";created_functions=" + helperBootstrap.createdFunctions());

            if (symbolInfo != null) {
                log.appendMsg("symbol_identity=verified;symbol_kind=" + symbolInfo.kind()
                    + ";symbol_sha256=" + symbolInfo.sha256()
                    + ";symbol_guid=" + symbolInfo.guid()
                    + ";symbol_age=" + Integer.toUnsignedLong(symbolInfo.age())
                    + ";symbol_processor=" + symbolInfo.processor()
                    + ";symbol_application=queued-xenon-analyzer");
            }

            log.appendMsg(appliedPatch == null
                ? "Xenon360 " + x.containerMagic + " import complete" : "Xenon360 XEXP import complete");
            log.appendMsg("container_magic=" + x.containerMagic
                + ";pe_preferred_image_base=" + Long.toHexString(x.peImageBase));
            log.appendMsg("source_sha256=" + sourceHash);
            if (appliedPatch != null) {
                log.appendMsg("base_sha256=" + baseHash
                    + ";xexp_source_version=" + appliedPatch.patch().sourceVersionHex()
                    + ";xexp_target_version=" + appliedPatch.patch().targetVersionHex()
                    + ";xexp_target_encryption=" + appliedPatch.targetEncryption()
                    + ";xexp_target_compression=" + appliedPatch.targetCompression()
                    + ";xexp_blocks=" + appliedPatch.payloadInfo().blockCount()
                    + ";xexp_records=" + appliedPatch.payloadInfo().recordCount()
                    + ";xexp_zero=" + appliedPatch.payloadInfo().zeroRecords()
                    + ";xexp_copy=" + appliedPatch.payloadInfo().copyRecords()
                    + ";xexp_lzx_delta=" + appliedPatch.payloadInfo().lzxDeltaRecords());
            }
            log.appendMsg("key_kind=" + effectiveKeyKind + ";sections=" + x.sections.size());
            if (x.compression == 2)
                log.appendMsg("normal_lzx_window=" + x.normalWindowSize + ";normal_blocks=" + x.normalBlockCount
                    + ";normal_lzx_bytes=" + x.normalLzxBytes + ";normal_trailing_bytes=" + x.normalTrailingBytes);
            log.appendMsg("pdata_records=" + x.pdata.size() + ";invalid_or_padding=" + invalid
                + ";duplicate_seeds=" + duplicate + ";missing_function_seeds=" + missing);
            log.appendMsg("entry_point=" + (x.entryPoint == 0 ? "none" : Long.toHexString(x.entryPoint)) + ";image_base=" + program.getImageBase());
            log.appendMsg(symbolInfo == null
                ? "Run normal Auto Analysis."
                : "Validated symbol file queued for Xenon360 PDB/XDB analyzer. Run normal Auto Analysis.");
        }
        catch (CancelledException e) { throw e; }
        catch (Exception e) { throw new IOException("Xenon360 mapping failed: " + e.getMessage(), e); }
    }

    private static String stringOption(List<Option> options, String name) {
        if (options == null) return null;
        for (Option option : options)
            if (option.getName().equals(name)) {
                Object value = option.getValue();
                return value == null ? null : value.toString();
            }
        return null;
    }

    private static String importKey(String library, XexImage.ImportRecord record) {
        return record.named()
            ? library + ":name:" + record.symbolName()
            : library + ":ord:" + record.ordinal();
    }

    private static String safeLocalName(String name) {
        return name.replaceAll("[^A-Za-z0-9_@$?]", "_");
    }

    private void importSymbols(Program program, XexImage x, TaskMonitor monitor,
            MessageLog log, Options info, AddressSet executable) throws Exception {
        ExternalManager external = program.getExternalManager();
        Map<String, ExternalLocation> locations = new HashMap<>();
        Set<String> functions = new HashSet<>();
        for (XexImage.LibraryGroup group : x.libraries)
            for (XexImage.ImportRecord record : group.records())
                if (record.kind() == 1 || record.kind() == 2)
                    functions.add(importKey(group.name(), record));
        int slots = 0, thunks = 0, unknown = 0, namedPeRecords = 0;
        int resolvedRecords = 0, unresolvedRecords = 0;
        Set<String> resolvedKeys = new HashSet<>();
        Set<String> unresolvedKeys = new HashSet<>();
        for (XexImage.LibraryGroup group : x.libraries) {
            monitor.checkCancelled();
            log.appendMsg("import_library=" + group.name() + ";records=" + group.records().size()
                + ";version=" + Long.toHexString(group.version())
                + ";minimum_version=" + Long.toHexString(group.minimumVersion()));
            for (XexImage.ImportRecord record : group.records()) {
                monitor.checkCancelled();
                if (record.kind() > 2) { unknown++; continue; }
                if (record.named()) namedPeRecords++;
                String key = importKey(group.name(), record);
                XenonOrdinalResolver.Export resolved = null;
                String label;
                String local;
                boolean directlyNamed = record.named();
                if (directlyNamed) {
                    label = record.symbolName();
                    local = safeLocalName(record.symbolName());
                    resolvedRecords++;
                    resolvedKeys.add(key);
                }
                else {
                    resolved = XenonOrdinalResolver.resolve(group.name(), record.ordinal());
                    String ordinalLabel = String.format(Locale.ROOT, "ord_%04x", record.ordinal());
                    if (resolved != null) {
                        label = resolved.name();
                        local = resolved.name();
                        resolvedRecords++;
                        resolvedKeys.add(key);
                    }
                    else {
                        label = ordinalLabel;
                        local = group.name().replaceAll("[^A-Za-z0-9_]", "_") + "_" + ordinalLabel;
                        unresolvedRecords++;
                        unresolvedKeys.add(key);
                    }
                }

                ExternalLocation location = locations.get(key);
                if (location == null) {
                    boolean functionImport = functions.contains(key)
                        || (resolved != null && resolved.function());
                    location = functionImport
                        ? external.addExtFunction(group.name(), label, null, SourceType.IMPORTED)
                        : external.addExtLocation(group.name(), label, null, SourceType.IMPORTED);
                    locations.put(key, location);
                }
                Address at = program.getAddressFactory().getDefaultAddressSpace().getAddress(record.address());
                executable.delete(at, at.addNoWrap(3));

                if (record.kind() == 0 || record.kind() == 2) {
                    program.getSymbolTable().createLabel(
                        at, "__imp__" + local, SourceType.IMPORTED);
                    // Type-0 XEX import records are data metadata. Kind-2 records are
                    // legacy XEX? PE IAT function slots. Both are pointer/data locations,
                    // not executable thunk seeds.
                    program.getListing().createData(at, DWordDataType.dataType);
                    program.getReferenceManager().addExternalReference(
                        at, -1, location, SourceType.IMPORTED, RefType.DATA);
                    slots++;
                    continue;
                }

                if (!x.executable(record.address(), 4)) {
                    throw new IOException(
                        "Import thunk record is not executable: " + at);
                }

                // Type-1 import records are thunk metadata seeds. Do NOT create
                // defined data at the entry point: Ghidra forbids a Function entry
                // on defined data. Model the thunk relation directly while retaining
                // the original four bytes unmodified.
                Function target = location.getFunction();
                if (target == null) {
                    throw new IOException(
                        "External import function was not created for " + key);
                }
                Function thunk = program.getFunctionManager().createThunkFunction(
                    "__thunk__" + local,
                    program.getGlobalNamespace(),
                    at,
                    new AddressSet(at, at.addNoWrap(3)),
                    target,
                    SourceType.IMPORTED);
                String resolvedText = record.named()
                    ? ("resolved_name=" + record.symbolName() + ";source=pe-import-name")
                    : resolved == null ? "unresolved"
                    : ("resolved_name=" + resolved.name() + ";source=" + XenonOrdinalResolver.SOURCE_ID);
                thunk.setComment("XEX import thunk metadata for " + key + "; " + resolvedText
                    + ". Four-byte metadata seed only; original bytes retained, not a recovered runtime stub body.");
                thunks++;
            }
        }
        info.setInt("Import library groups", x.libraries.size());
        info.setInt("Import slots", slots); info.setInt("Import thunk metadata seeds", thunks);
        info.setInt("Unknown import records", unknown);
        info.setInt("Named PE import records", namedPeRecords);
        info.setInt("Resolved import records", resolvedRecords);
        info.setInt("Unresolved import records", unresolvedRecords);
        info.setInt("Resolved unique imports", resolvedKeys.size());
        info.setInt("Unresolved unique imports", unresolvedKeys.size());
        log.appendMsg("import_slots=" + slots + ";import_thunk_metadata_seeds=" + thunks
            + ";unknown=" + unknown + ";named_pe_records=" + namedPeRecords);
        log.appendMsg("import_names_resolved_records=" + resolvedRecords
            + ";unresolved_records=" + unresolvedRecords
            + ";resolved_unique=" + resolvedKeys.size()
            + ";unresolved_unique=" + unresolvedKeys.size()
            + ";source=" + XenonOrdinalResolver.SOURCE_ID);
    }
}
