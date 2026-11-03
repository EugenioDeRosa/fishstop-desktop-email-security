"""Generation-order contract between the bundled Ollama runtime and FAST.

With a JSON schema passed in ``format``, Ollama compiles it to a grammar that
emits only the *required* keys, in alphabetical order (observed with
v0.32.15). The order is part of what FAST learns: the primary pass writes
``explanation`` before ``verdict``, so the model explains before deciding.
FAST Lite v7.1 and v8 were trained on exactly the orders below.

If a schema's required keys change, or the bundled Ollama version changes,
the trained order may no longer match what the app receives. The tests in
``tests/test_output_key_order_contract.py`` then fail on purpose:

* re-run the live check against the new runtime
  (``FISHSTOP_OLLAMA_CONTRACT_MODEL=<model> python -m pytest
  tests/test_output_key_order_contract.py``);
* if the real order differs, regenerate/retrain the dataset, or rename keys
  (for example ``a_verdict``) to force the intended order, then update this
  file together with the dataset version.
"""

# Version on which the orders below were observed. Must equal the runtime
# pinned in src-tauri/src/ollama_runtime.rs and scripts/download_ollama_runtime.py.
OLLAMA_CONTRACT_VERSION = "v0.32.15"

# Dataset generations trained on these orders.
TRAINED_DATASETS = ("fishstop-fast-lite-v7.1", "fishstop-fast-lite-v8")

# Request stage -> top-level keys in the order the model generates them.
TRAINED_KEY_ORDER: dict[str, list[str]] = {
    "primary": ["action", "ambiguity", "channel", "evidence", "explanation", "quote", "signals", "verdict"],
    "identity": ["name", "quote", "role", "source"],
    "content-risk-verification": ["basis", "explanation", "quote", "verdict"],
    "verifier:intent": ["action", "channel", "evidence"],
    "verifier:payment_diversion": ["payment_change_evidence", "payment_destination_change", "scam_type"],
    "verifier:security_lure": [
        "claimed_brand", "evidence", "identity_deception", "requested_external_action", "security_alert",
    ],
    "verifier:extortion": [
        "amount", "evidence", "extortion", "payment_asset", "payment_method", "sextortion", "threat_evidence",
    ],
    # The adaptive audit nests one verifier object per enabled check.
    "audit": ["extortion", "intent", "payment_diversion", "security_lure"],
}


def expected_generation_order(schema: dict) -> list[str]:
    """Top-level key order Ollama v0.32.15 generates for ``schema``."""
    return sorted(schema.get("required") or [])


def schemas_by_stage() -> dict[str, dict]:
    """Every structured-output schema the analysis pipeline sends to Ollama."""
    from . import llm_context_analyzer as llm
    return {
        "primary": llm.PRIMARY_OUTPUT_SCHEMA,
        "identity": llm.IDENTITY_EXTRACTION_SCHEMA,
        "content-risk-verification": llm.CONTENT_RISK_VERIFICATION_SCHEMA,
        "verifier:intent": llm.TARGETED_INTENT_SCHEMA,
        "verifier:payment_diversion": llm.PAYMENT_DIVERSION_SCHEMA,
        "verifier:security_lure": llm.SECURITY_LURE_SCHEMA,
        "verifier:extortion": llm.EXTORTION_SCHEMA,
        "audit": llm._adaptive_audit_schema(list(llm._AUDIT_SCHEMAS)),
    }
