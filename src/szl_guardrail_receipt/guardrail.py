# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2024 SZL Contributors
"""Guardrail verdicts and a trivial, dependency-free rule-based guardrail.

This module defines the *shape* of a guardrail verdict (:class:`GuardrailVerdict`)
so the receipt layer can wrap ANY guardrail — Llama-Guard, NeMo-Guardrails,
guardrails-ai, a ProtectAI injector detector, or your own callable — without
bundling their weights. You adapt an external guardrail by mapping its output to
a :class:`GuardrailVerdict` (see :func:`verdict_from_callable`).

It also ships :class:`RuleBasedGuardrail`: a tiny, deterministic, stdlib-only
guardrail so the whole pipeline RUNS with zero external downloads — useful for
demos, tests, and CI.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Callable, Dict, List, Optional

#: Honest, brand-stable Λ label. Λ-uniqueness is machine-checked *open*
#: (Conjecture 1); a receipt must never report Λ as "proven" or "green".
LAMBDA_LABEL = "Λ = Conjecture 1 — never green"


@dataclasses.dataclass
class GuardrailVerdict:
    """A single guardrail allow/deny decision, guardrail-agnostic.

    Args:
        allowed: True to allow the action, False to deny/block it.
        guardrail_name: Identifier of the guardrail that decided (e.g.
            ``"meta-llama/Llama-Guard-3-8B"`` or ``"szl-rule-based-guardrail"``).
        guardrail_version: Version string of that guardrail.
        reason: Short, human-readable explanation of the decision.
        categories: Policy categories that fired (empty when allowed).
        lambda_score: Optional advisory Λ score in ``[0, 1]`` (heuristic, never
            a proof). ``None`` when the guardrail reports no score — never
            fabricated.
        metadata: Free-form extra context from the underlying guardrail.
    """

    allowed: bool
    guardrail_name: str
    guardrail_version: str
    reason: str = ""
    categories: List[str] = dataclasses.field(default_factory=list)
    lambda_score: Optional[float] = None
    metadata: Dict[str, object] = dataclasses.field(default_factory=dict)


def verdict_from_callable(
    fn: Callable[[str], object],
    text: str,
    *,
    guardrail_name: str,
    guardrail_version: str,
) -> GuardrailVerdict:
    """Adapt an arbitrary guardrail callable into a :class:`GuardrailVerdict`.

    The callable may return a bool (True == allowed), or a mapping with any of
    ``allowed`` / ``blocked`` / ``flagged`` / ``reason`` / ``categories`` /
    ``lambda_score``. This is the seam for wrapping Llama-Guard / NeMo /
    guardrails-ai without this package importing them.

    Args:
        fn: The guardrail callable, applied to *text*.
        text: The input being screened.
        guardrail_name: Name to record on the verdict.
        guardrail_version: Version to record on the verdict.

    Returns:
        A normalised :class:`GuardrailVerdict`.
    """
    out = fn(text)
    if isinstance(out, bool):
        return GuardrailVerdict(
            allowed=out,
            guardrail_name=guardrail_name,
            guardrail_version=guardrail_version,
            reason="allowed" if out else "denied by guardrail callable",
        )
    if isinstance(out, dict):
        if "allowed" in out:
            allowed = bool(out["allowed"])
        elif "blocked" in out:
            allowed = not bool(out["blocked"])
        elif "flagged" in out:
            allowed = not bool(out["flagged"])
        else:
            raise ValueError(
                "guardrail callable dict must carry one of "
                "'allowed'/'blocked'/'flagged'"
            )
        score = out.get("lambda_score")
        return GuardrailVerdict(
            allowed=allowed,
            guardrail_name=guardrail_name,
            guardrail_version=guardrail_version,
            reason=str(out.get("reason", "allowed" if allowed else "denied")),
            categories=list(out.get("categories", [])),
            lambda_score=float(score) if isinstance(score, (int, float)) else None,
            metadata={
                k: v
                for k, v in out.items()
                if k
                not in {"allowed", "blocked", "flagged", "reason", "categories", "lambda_score"}
            },
        )
    raise TypeError(f"unsupported guardrail return type: {type(out).__name__}")


class RuleBasedGuardrail:
    """A trivial, deterministic guardrail — zero downloads, stdlib only.

    Screens text against a small set of documented regex rules (prompt
    injection, secret exfiltration, self-harm). It is intentionally minimal:
    its job is to make the receipt pipeline runnable and testable end-to-end,
    NOT to be a production safety classifier. For real coverage, wrap a proper
    guardrail via :func:`verdict_from_callable`.
    """

    name = "szl-rule-based-guardrail"
    version = "0.1.0"

    #: (category, [compiled patterns]) — deny if any pattern matches.
    RULES: Dict[str, List[str]] = {
        "prompt-injection": [
            r"ignore (all |the )?(previous|prior|above) (instructions|prompts?)",
            r"disregard (all |the )?(previous|prior|above|your) (instructions|rules)",
            r"reveal (your )?(system )?prompt",
            r"you are now (in )?(developer|dan|jailbreak) mode",
        ],
        "secret-exfiltration": [
            r"\b(api[_-]?key|secret[_-]?key|password|private[_-]?key)\b.*(print|reveal|show|dump|exfiltrat)",
            r"(print|reveal|show|dump|leak)\b.*\b(api[_-]?key|secret|password|token|credential)s?\b",
        ],
        "self-harm": [
            r"\bhow (to|do i) (kill|hurt|harm) (myself|yourself)\b",
        ],
    }

    def __init__(self) -> None:
        self._compiled = {
            cat: [re.compile(p, re.IGNORECASE) for p in pats]
            for cat, pats in self.RULES.items()
        }

    def check(self, text: str) -> GuardrailVerdict:
        """Screen *text* and return a :class:`GuardrailVerdict`.

        The advisory ``lambda_score`` is a documented, deterministic heuristic
        (NOT a measured or proven quantity): ``1.0`` when nothing fires, else
        ``max(0.0, 1 - 0.5 * hits)``. It is labelled advisory everywhere.
        """
        hits: List[str] = []
        matched_rules: List[str] = []
        for cat, patterns in self._compiled.items():
            for pat in patterns:
                if pat.search(text):
                    hits.append(cat)
                    matched_rules.append(pat.pattern)
                    break
        allowed = not hits
        score = 1.0 if allowed else max(0.0, 1.0 - 0.5 * len(hits))
        reason = (
            "no rule matched"
            if allowed
            else "matched policy categories: " + ", ".join(hits)
        )
        return GuardrailVerdict(
            allowed=allowed,
            guardrail_name=self.name,
            guardrail_version=self.version,
            reason=reason,
            categories=hits,
            lambda_score=score,
            metadata={
                "matched_rules": matched_rules,
                "score_formula": "1.0 if clean else max(0, 1 - 0.5*hits)",
                "score_kind": "advisory heuristic — not measured, not a proof",
            },
        )
