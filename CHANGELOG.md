# Changelog

## 0.8.2

- Recover physically bounded unsigned 16-bit relative switch tables, including zero offsets and supported nested dispatches. Preserve symbols, instruction ownership, cancellation rollback and repeatability.
- Build separate Ghidra 12.1.4 / Java 21 and Ghidra 12.2 / Java 25 packages from shared source. Adapt only the loader-option UI API where the releases differ.
- Check explicit regression receipts, inspect nested release archives, target Java bytecode, and package only curated runtime resources.
- Add reproducible release qualification on GitHub-hosted Linux runners with pinned downloads and separate artifacts. Workflow configuration alone is not a qualification result.
- Exclude historical workstation-specific research runners from distributed source. Retain third-party notices and synthetic regression fixtures.

## 0.8.1

- Correct `lvrx128` decoding and partial-vector memory behavior.
- Implement native integer lane semantics for `vpermwi128` and `vrlimi128`, preserving aliased operands and untouched lanes.
- Preserve corrected data references and established symbol/ownership protections.

## 0.8.0

- Add Ghidra 12.2 support, integrated helper modeling, bounded byte-indexed switch recovery, Havok metadata/callback evidence and cross-architecture comparison.
- Add deterministic extension packaging and native p-code, cancellation, preservation and idempotency checks.

## Limits

Opaque floating-point/record VMX userops, arbitrary writable or multi-block switch forms, exact retail SDK/source identities and historical native decompiler timeout behavior remain limited. Comparisons do not automatically transfer names, layouts or prototypes. Local tests are separate from user visual acceptance and physical-console validation.
