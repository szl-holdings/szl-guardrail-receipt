<!-- PROPOSE-ONLY / DO-NOT-MERGE. Study document only. No code, config, or workflow change is proposed by this file. -->
# LEADERS-STUDY -- szl-guardrail-receipt (tranche 6, 2026-11-24)

> **PROPOSE-ONLY / DO-NOT-MERGE.** Per-repo-domain public-surface study card from the round-2 leader pack.
> Nothing here is approved for implementation. Merge requires a separate governing review plus a fresh owner GO naming repo, PR, and pin.

## 0. Scope gate

Study-only. This PR adds exactly one documentation file (this file). No adapter change, no dependency change, no PyPI release. All absorb candidates are UNAPPROVED.

## 1. Current state (measured evidence, 2026-11-24 qualification)

- Repo: szl-holdings/szl-guardrail-receipt, main tip at qualification 5ea08c0234f95e79bd34dd112e68a46241509298, 42 files, zero open PRs at scan time. Published on PyPI as szl-guardrail-receipt (README badge, measured).
- Positioning (README): guardrail tools output a verdict but no verifiable, replayable, signed audit record. This package is a thin, dependency-light adapter that emits a signed, hash-chained DSSE decision receipt on each allow/deny, field-aligned with governed-receipt-spec, offline-verifiable with one command.
- Named wrap targets (README): Llama-Guard, NeMo-Guardrails, guardrails-ai, ProtectAI injector detectors.
- Receipt record includes the decision, the guardrail that made it, a hash of the screened input, an advisory Lambda score, an honest-blocked flag, a timestamp. Badges measured: PyPI, Python versions, OpenSSF Scorecard, CI, Apache-2.0.

## 2. Field leaders (public-surface study, round-2 leader pack + README-named tools)

| # | Leader | Public source | Leads at |
|---|---|---|---|
| L1 | Meta Llama Guard | public Llama Guard model + model cards on HF | The canonical verdict model surface with published evaluations |
| L2 | NVIDIA NeMo Guardrails | github.com/NVIDIA/NeMo-Guardrails OSS | Rail-based guardrail toolkit, wide integration surface |
| L3 | Guardrails AI | github.com/guardrails-ai (OSS + product) | Validator-grammar wrapping pattern with structured outputs |
| L4 | Protect AI modelscan | github.com/protectai modelscan (HF injection scanning) | Public security-scanner OSS culture for ML models |

## 3. Honest gaps (this repo vs the leaders)

- Gap A: adapter coverage breadth vs leaders' integration toolkits: named targets exist but no published per-adapter version matrix (leader toolkits document rails/validators per version).
- Gap B: no published conformance vectors per adapter class (mutated receipt must-e-fail suite) versus leaders' evaluation cultures.
- Gap C: the screened-input hash privacy story (what is hashed, retention, cross-references) is thin relative to leaders' policy docs.
- Honest non-gap (the moat): NO leader emits a signed, replayable, hash-chained receipt of an allow/deny decision. Convergence evidence: the estate design matches the IETF enforcement-attestation-receipt direction (draft-chueayen-attestation-receipts-02).

## 4. Absorb candidates A1-A4 (ALL UNAPPROVED)

- A1: Per-adapter parity matrix doc (guardrail, version, decision surface, receipt-field mapping). Applicability test: every mapped field one-to-one; unmapped fields fail closed.
- A2: Negative conformance vectors per adapter class. Applicability test: verifier rejects every mutated receipt class offline.
- A3: Screened-input privacy doc (hash algorithm, salt/derivation, retention, no plaintext). Applicability test: a third party can state exactly what the receipt does and does not reveal.
- A4: Study-only citation of draft-chueayen-attestation-receipts as convergence evidence in docs. Applicability test: citation only; adapter semantics unchanged.

## 5. Open questions A5-A6 (governing gates)

- A5 (Kimi lap): should receipt fields absorb IETF enforcement-receipt field names where they converge (A1-adjacent), or stay governed-receipt-spec-aligned only and cite the draft externally?
- A6 (owner/Kimi): retention policy for decision receipts with adversarial inputs: are blocked-input receipts quarantined (warehouse doctrine) or exempt because only hashes ever leave the guardrail?

## 6. Non-goals

No implementation in this PR. No verdict-model claim (this package judges nothing itself), no security-scanner claim, no new adapter added. No merge without governing review + fresh owner GO naming repo, PR, and pin.

## 7. Markers and receipts

LEADERS_STUDY_TRANCH6_CARD_5_OF_6 | PROPOSE_ONLY_DNM | qualification tip 5ea08c02 | erf scan C:/SZL/edge-debug/sp9_census.txt | qualification receipt ft_h4_t6qual.json (2026-11-24T13:46:23Z) | leader pack round2-leader-pack.md.
