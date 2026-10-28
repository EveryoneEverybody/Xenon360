# Third-party notices

Xenon360 is built on Ghidra and uses a small amount of implementation data or derived code from other open-source Xbox 360 projects. Full license texts are kept under `licenses/`.

- **Ghidra**: the Xenon language build uses Ghidra's PowerPC language sources as its base. Ghidra is licensed under Apache-2.0. The build also copies Ghidra's license into the packaged extension.
- **Xenia**: Xbox 360 export-name tables, format behavior, and vector memory semantics are referenced from Xenia. The applicable BSD notice is included as `LICENSE-XENIA.txt`. The 0.8 partial-vector regression reference is `src/xenia/cpu/ppc/ppc_emit_altivec.cc` at commit `121bf93cbe2c23fe0a47f1f43e3f050df46e976d`.
- **360tools**: the Java LZX decoder is adapted from the MIT-licensed XEX2 decoder in 360tools. The MIT notice is included as `LICENSE-360TOOLS.txt`.
- **KodaSec/wince-decompr**: 360tools identifies this MIT-licensed decoder as an upstream reference for its LZX implementation. Its original copyright and license are retained as `LICENSE-WINCE-DECOMPR.txt` to cover that transitive provenance.
- **idaxex**: early XEX layout and integrity behavior were cross-checked against idaxex. Its BSD-3-Clause notice is included as `LICENSE-IDAXEX.txt`.
- **Xbox-360-Crypto**: Xbox signature and crypto behavior were cross-checked against Xbox-360-Crypto. Its BSD-3-Clause notice is included as `LICENSE-XBOX-360-CRYPTO.txt`.

These projects are not runtime dependencies of the extension.

The Gradle Wrapper is used only to build the project. Its Apache-2.0 license is included as `licenses/LICENSE-GRADLE.txt`. Gradle is not required to install or use the extension.

## Distribution boundaries

The Java extension and Xenon-specific language additions are original project work except for the adaptations listed above. Generated PowerPC language resources retain Ghidra's notices. The runtime uses libraries provided by the selected Ghidra installation; third-party JARs are not bundled inside the extension JAR.

Legacy ordinal observations contain module/ordinal/export-name facts checked at matching export and symbol addresses. They contain no SDK headers, implementation bodies, private debug records, symbol files, or proprietary libraries. Ambiguous generations retain ordinal fallbacks. These observations are not a redistributable copy of an SDK.

Havok layout recognition, bounded switch recovery and the synthetic test fixtures are project implementations. Proprietary Havok, Xbox/XDK and Direct3D libraries and headers, retail executables, and original research projects are neither build inputs nor distributed files. Public Valve Source SDK code and modified Ghidra/GhidraXenon implementations were comparison references only; their source, headers, scripts and libraries are not vendored. Public accessibility alone is not treated as permission to redistribute them.

Reference projects: [Ghidra](https://github.com/NationalSecurityAgency/ghidra), [Xenia](https://github.com/xenia-project/xenia), [360tools](https://github.com/sp00nznet/360tools), [idaxex](https://github.com/emoose/idaxex), and [Xbox-360-Crypto](https://github.com/GoobyCorp/Xbox-360-Crypto). Their respective license texts govern the listed third-party material; the project Apache-2.0 license does not replace them.
