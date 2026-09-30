<p align="center">
  <img src="assets/Xenon360_banner.png" alt="Xenon360" width="100%">
</p>

# Xenon360

Xenon360 adds Xbox 360 executable support to Ghidra: an XEX/XEXP loader, a Xenon PowerPC/VMX128 language, import naming, native PDB/XDB symbols, and automatic compiler-helper modeling.

Xenon360 is an independent open-source project. It is not affiliated with, sponsored by, or endorsed by Microsoft. Xbox and Xbox 360 are trademarks of Microsoft.

## Install

Use the extension ZIP built for your Ghidra version. In Ghidra's project window, open **File > Install Extensions**, click **+**, and select the ZIP. Restart Ghidra, import your executable using **Xenon360 XEX**, and run Auto Analysis.

No build tools, PowerShell, or follow-up repair scripts are required to use the extension. The ZIP contains Java classes and language data, not host-specific executables.

For XEXP patches, select the matching source executable with the **Base XEX** picker. For native symbols, use the **PDB/XDB** picker. The default `public-symbols` mode loads types and public symbols; `all` enables Ghidra's full Universal PDB analysis.

## Supported formats

XEX0, XEX?, XEX%, XEX-, XEX1, XEX2, and XEXP/DELTA are supported, including NONE, BASIC, and NORMAL/LZX reconstruction and the supported retail/development encryption variants.

The language ID is `PowerPC:BE:64:Xenon-VMX128-32addr`. The module remains named `XenonVMX128` to preserve existing project bindings.

Unknown imports retain deterministic module-and-ordinal names. Conflicting legacy ordinal observations are not assigned a guessed name. Native symbol loading checks GUID, age, processor identity, and file integrity before application.

## Ghidra on macOS

Use a working Ghidra installation with its native components built for your Mac. Ghidra 12.1.4 does not bundle those Mac binaries. Follow Ghidra's **Getting Started > Building Native Components** instructions once when setting up Ghidra. The Xenon360 ZIP itself is unchanged across platforms.

## Build from source

Requirements: Ghidra 12.1.x and JDK 21 or newer. The same Gradle build is used on Windows, Linux, and macOS.

Windows:

```bat
.\gradlew.bat "-PGHIDRA_INSTALL_DIR=C:\Tools\ghidra_12.1.4_PUBLIC" buildExtension
```

Linux and macOS:

```sh
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC buildExtension
```

`GHIDRA_INSTALL_DIR` may also be set as an environment variable. Set `JAVA_HOME` to select a JDK. Paths containing spaces must be quoted.

The build prepares the Xenon language, compiles the loader, runs the parser/patch/import-name tests, and creates `dist/ghidra_<version>_XenonVMX128_0.7.0.zip` with a SHA-256 checksum file. It does not change your installed extension or Ghidra projects.

The wrapper downloads Gradle 9.1.0 on first use and verifies its SHA-256 checksum. Later builds use the cached distribution. No Xbox SDK or game files are needed. An offline machine needs the pinned Gradle distribution cached or installed in advance; `--offline` does not download the wrapper distribution for you.

## Tests

`buildExtension` runs the standalone regression tests and checks language preparation with both LF and CRLF line endings. To also import a synthetic XEX in a disposable Ghidra instance, run:

```sh
./gradlew -PGHIDRA_INSTALL_DIR=/path/to/ghidra buildExtension smokeTest
```

Use `gradlew.bat` on Windows. The smoke test installs only inside `build/smoke`, verifies automatic helper modeling, and never runs a repair script. Its logs are kept there. This does not replace visual testing of the import dialogs or analysis of real executables.

## Source handling

Xenon360 does not execute game code or modify source executables. Patches are reconstructed in memory.

The repository and release package do not include game executables, game code, game symbols, Xbox SDK files, or other proprietary runtime content. Users supply their own XEX/XEXP files and, when available, their own PDB/XDB symbol files.

Signature and hash checks are recorded as diagnostics; older integrity schemes are not treated as modern XEX2 validation.

Third-party notices are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md), with license texts under [licenses](licenses/).

## License

Copyright 2026 EveryoneEverybody.

Xenon360 is licensed under the Apache License 2.0. See [LICENSE](LICENSE). Third-party components and derived material remain under their original licenses as listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
