# Third-party notices

Xenon360 is built on Ghidra and uses a small amount of implementation data or derived code from other open-source Xbox 360 projects. Full license texts are kept under `licenses/`.

- **Ghidra**: the Xenon language build uses Ghidra's PowerPC language sources as its base. Ghidra is licensed under Apache-2.0. The build also copies Ghidra's license into the packaged extension.
- **Xenia**: Xbox 360 export-name tables and format behavior are referenced from Xenia. The applicable BSD notice is included as `LICENSE-XENIA.txt`.
- **360tools**: the Java LZX decoder is adapted from the MIT-licensed XEX2 decoder in 360tools. The MIT notice is included as `LICENSE-360TOOLS.txt`.
- **idaxex**: early XEX layout and integrity behavior were cross-checked against idaxex. Its BSD-3-Clause notice is included as `LICENSE-IDAXEX.txt`.
- **Xbox-360-Crypto**: Xbox signature and crypto behavior were cross-checked against Xbox-360-Crypto. Its BSD-3-Clause notice is included as `LICENSE-XBOX-360-CRYPTO.txt`.

These projects are not runtime dependencies of the extension.

The Gradle Wrapper is used only to build the project. Its Apache-2.0 license is included as `licenses/LICENSE-GRADLE.txt`. Gradle is not required to install or use the extension.
