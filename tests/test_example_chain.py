# SPDX-License-Identifier: Apache-2.0
"""The committed sample chain is generator output, not a hand-edited file."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from szl_guardrail_receipt import crypto_available

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "examples" / "guardrail-receipt-chain.json"


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "guardrail_example_generate", ROOT / "examples" / "generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sample_names_no_verify_key_url_for_the_ephemeral_key():
    # The sample is signed with an ephemeral key that is never published, so no
    # envelope may point readers at a key location (the retired demo Space was one).
    for record in json.loads(SAMPLE.read_text(encoding="utf-8")):
        assert "verify_key_url" not in record["envelope"]


@pytest.mark.skipif(not crypto_available(), reason="signing extra not installed")
def test_sample_payloads_match_a_fresh_generator_run(tmp_path):
    out = tmp_path / "chain.json"
    assert _load_generator().main(["--out", str(out)]) == 0
    fresh = json.loads(out.read_text(encoding="utf-8"))
    committed = json.loads(SAMPLE.read_text(encoding="utf-8"))
    assert [r["envelope"]["payload"] for r in fresh] == [
        r["envelope"]["payload"] for r in committed
    ]
    assert all("verify_key_url" not in r["envelope"] for r in fresh)


@pytest.mark.skipif(not crypto_available(), reason="signing extra not installed")
def test_explicit_verify_key_url_is_recorded_only_when_given(tmp_path):
    out = tmp_path / "chain.json"
    url = "https://keys.example.invalid/guardrail.pub"
    assert _load_generator().main(["--out", str(out), "--verify-key-url", url]) == 0
    for record in json.loads(out.read_text(encoding="utf-8")):
        assert record["envelope"]["verify_key_url"] == url
