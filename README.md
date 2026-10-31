<p align="center">
  <img src="assets/Xenon360_banner.png" alt="Xenon360" width="100%">
</p>

# Xenon360

Xenon360 0.8.3 is a Ghidra extension for loading and analyzing Xbox 360 executables. It includes an XEX/XEXP loader, a Xenon PowerPC/VMX128 processor language, and automatic analysis tools.

For updates, improvements, and known limitations, see the [GitHub Releases page](https://github.com/EveryoneEverybody/Xenon360/releases).

## Compatibility

**Ghidra 12.2 is the primary target.** Ghidra 12.1.4 is supported on a best-effort basis. Install the package built for your exact Ghidra version; the packages are not interchangeable.

| Ghidra | Required JDK | Extension ZIP |
|---|---|---|
| 12.2 | 25 | `ghidra_12.2_XenonVMX128_0.8.3.zip` |
| 12.1.4 | 21 | `ghidra_12.1.4_XenonVMX128_0.8.3.zip` |

The Xenon language version is **1.4**, with language ID `PowerPC:BE:64:Xenon-VMX128-32addr`. The extension module remains named `XenonVMX128` for compatibility with existing projects.

Back up existing projects and their original extension package before upgrading. Try 0.8.3 with a fresh import or a project copy, and keep a backup before accepting a language upgrade. Never open a project upgraded by Ghidra 12.2 in 12.1.4.

The packages contain no host-specific executables. Windows and Linux have been tested; macOS has not been qualified. On macOS, first ensure Ghidra works with the native components required for your Mac.

## Installation

1. Download the matching extension ZIP and verify it against the accompanying SHA-256 checksum.
2. In Ghidra's project window, choose **File > Install Extensions**, click **+**, and select the ZIP.
3. Restart Ghidra. If prompted to configure plugins, enable **XenonAnalysisPlugin**.

No build tools or follow-up repair scripts are needed. The plugin can also be enabled through **File > Configure > Configure All Plugins**, under Analysis.

## Basic usage

1. Create a local Ghidra project and choose **File > Import File**.
2. Select an executable you are authorized to analyze. Confirm **Xenon360 XEX** and the Xenon language above.
3. For an XEXP patch, select its matching executable with **Base XEX**. Optional native symbols can be selected with **PDB/XDB**; leave this empty if you have no matching symbols.
4. Open the program and accept normal **Auto Analysis**. Keep native switch analysis enabled and review the analysis log for warnings.

## Features

- XEX executable loading and XEXP patch reconstruction.
- Xenon PowerPC and VMX128 disassembly and decompilation support.
- Import naming and native PDB/XDB symbol loading, with symbol-identity checks.
- Automatic compiler-helper analysis, recovery of supported switch tables, and recognition of supported Havok metadata.
- Local analysis export and reference comparison through **Tools > Xenon360**. Comparison reports do not automatically apply names, types, or prototypes.

Coverage is incomplete, and unsupported cases may leave decompilation unfinished. Instruction support does not guarantee hardware-equivalent results. Advanced repair and callback-renaming options are disabled by default and can change saved analysis; use them only when you understand their effect on the project.

Xenon360 does not execute game code or modify source executables. It makes no network requests and contains no telemetry. Users supply their own executables and symbols; no proprietary SDK or game content is included or required for installation. Analysis exports can contain program names, hashes, symbols, and addresses; review them before sharing.

## Troubleshooting and removal

- **Version mismatch:** use the ZIP for your exact Ghidra version and the JDK listed above.
- **Loader or language missing:** restart Ghidra and check for duplicate XenonVMX128 installations. A separate XEX loader is unnecessary.
- **Symbols rejected:** verify that the PDB/XDB matches the executable. Ordinary executable loading does not require symbols.
- **Incomplete analysis:** review warnings and unsupported instructions. An adequate decompiler timeout can help, but it does not guarantee complete recovery.

To uninstall, close open programs, mark XenonVMX128 for removal in **File > Install Extensions**, and restart Ghidra. Removal does not undo changes saved in a project. Retain backups and the matching package for projects that require the Xenon language.

## Documentation and source

Release assets include the public source and license notices. Building requires the matching Ghidra/JDK pair above and Gradle 9.1.0; the included wrapper downloads Gradle on first use.

Set `JAVA_HOME` and `GHIDRA_INSTALL_DIR`, then run `./gradlew buildExtension` on Linux/macOS or `.\gradlew.bat buildExtension` on Windows. Quote paths containing spaces. The output ZIP and checksum are written to `dist/`.

## License and acknowledgments

Copyright 2026 EveryoneEverybody. Xenon360 is licensed under the [Apache License 2.0](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md) and [license texts](licenses/) for component licenses and acknowledgments.

Xenon360 is an independent open-source project, not affiliated with, sponsored by, or endorsed by Microsoft, Havok, or Valve Corporation. References to their technologies are for compatibility, identification, and technical research only.

Xbox, Xbox 360, Direct3D, and DirectX are trademarks of the Microsoft group of companies. Havok and Havok Physics are trademarks of Havok. Valve and Source are trademarks of Valve Corporation. All other trademarks are the property of their respective owners.
