# Changelog

## 0.1.3 (unreleased)

### Fixed

- Align runtime `__version__` with distribution metadata; add an installed-package version regression.
- Bind decoded receipt digests, wrapper claims, declared payload types, and exact signed payload bytes during verification (#14, #15).
- Distinguish structural-only integrity from authenticated verification; require authentication when a public key is supplied, including empty key inputs, and reject an empty CLI key filename (#15, #18, #20).
- Reject nonfinite JSON values before hashing or signing and reject nonboolean direct verdicts before emitting receipts (#19, #21).

### Packaging

- Sync the canonical release gate, including isolated installed-wheel probes and dependency checks, and add its wheel-isolation regressions.

The implementation fixes above are changes since 0.1.2 already present on main. This release preparation changes version identity, packaging validation, and tests. Earlier releases are documented in the repository's GitHub Releases.
