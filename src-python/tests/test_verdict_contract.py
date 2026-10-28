"""Python ↔ interface verdict contract.

Builds synthetic reports with the real static engine and the real semantic
policy (model output simulated), and keeps them in
test-fixtures/verdict-contract.json. scripts/test_verdict_contract.mjs runs the
interface assessment() on the same reports and checks that it agrees with the
Python final verdict. Regenerate after an intentional policy change with:

    FISHSTOP_WRITE_CONTRACT=1 python -m unittest tests.test_verdict_contract
"""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_detection_logic import QUOTED_FROM_RECIPIENT, analyze  # noqa: E402

from fishstop_engine.analyzer import llm_context_analyzer as llm  # noqa: E402

FIXTURE = Path(__file__).resolve().parents[2] / "test-fixtures" / "verdict-contract.json"
SVG = b'<svg xmlns="http://www.w3.org/2000/svg"><script>location="https://evil.example/"</script></svg>'
ICS = (b"BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nSUMMARY:Verifica account\r\n"
       b"ORGANIZER:mailto:it@other-org.example\r\nDESCRIPTION:Accedi qui https://portal.other-org.example/login\r\n"
       b"END:VEVENT\r\nEND:VCALENDAR\r\n")


def semantic(action="informational", channel="none", risk="benign", evidence="", rationale="Ordinary message."):
    return {"summary": "Synthetic message.", "action": action, "channel": channel, "evidence": evidence,
            "signals": [], "ambiguity": "low", "risk_assessment": risk,
            "risk_evidence": evidence if risk != "benign" else "", "risk_rationale": rationale}


def scenarios():
    yield "legitimate_order", analyze("Shop <orders@shop.example>", "Ordine spedito", to="mario@gmail.com",
        html='<a href="https://www.shop.example/orders/1">Visualizza ordine</a>'), semantic()
    yield "cross_domain_reply_to", analyze("News <news@shop.example>", "Novità", reply_to="care@shop-help.example",
        html='<a href="https://www.shop.example/new">Novità</a>'), semantic()
    yield "masked_brand_link", analyze("Banca <avvisi@notifiche-banca.example>", "Accesso",
        html='<a href="https://account-check.example/login">https://www.intesasanpaolo.com/login</a>'), semantic(
        "visit_link", "link", evidence="Accesso")
    yield "fake_reply", analyze("Luca <luca@fornitore.example>", "RE: documento", text="Ti allego il documento."), semantic()
    yield "fabricated_thread", analyze("Luca <luca@fornitore-amministrazione.example>", "RE: Fattura 2026/118",
        text=QUOTED_FROM_RECIPIENT, to="mario.rossi@azienda.it"), semantic()
    yield "svg_script", analyze("Voice <vm@voice.example>", "Messaggio vocale", text="Ascolta l'allegato.",
        attachments=[("VM.svg", "image/svg+xml", SVG)]), semantic("open_attachment", "attachment", evidence="Ascolta")
    yield "executable_attachment", analyze("Fornitore <info@fornitore.example>", "Ordine", text="In allegato.",
        attachments=[("Ordine.exe", "application/octet-stream", b"MZ" + b"\x00" * 200)]), semantic()
    yield "sender_lookalike", analyze("Fatture <amministrazione@paypa1.com>", "IBAN", text="Nuove coordinate."), semantic()
    yield "ipfs_link", analyze("Docs <share@docs-share.example>", "Documento condiviso",
        html='<a href="https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi/x.html">Apri</a>'), semantic(
        "visit_link", "link", evidence="Apri")
    yield "calendar_invite", analyze("IT <it@company.example>", "Invito", text="Invito allegato.",
        attachments=[("invite.ics", "text/calendar", ICS)]), semantic()
    yield "ai_grounded_phishing", analyze("Team <team@service.example>", "Premio",
        text="Hai vinto un premio inatteso, inserisci la password per riceverlo."), semantic(
        "provide_credentials", "reply", "phishing", "inserisci la password per riceverlo",
        "Credential request disguised as a prize.")
    yield "iban_change_foreign", analyze("Fornitore <amministrazione@fornitore.it>", "Coordinate",
        text="Vi comunichiamo le nuove coordinate bancarie: LT12 1000 0111 0100 1000."), semantic()
    yield "regular_invoice_iban", analyze("Fornitore <amministrazione@fornitore.it>", "Fattura 118",
        text="In allegato la fattura. Pagamento su IBAN IT60 X054 2811 1010 0000 0123 456 come sempre."), semantic()
    yield "personalised_login_link", analyze("IT <it@it-portal.example>", "Accesso",
        html='<a href="https://login.example.com/#mario.rossi@azienda.it">Accedi</a>'), semantic("visit_link", "link", evidence="Accedi")
    yield "missing_dkim_only", analyze("Shop <news@shop.example>", "Informazioni", text="Orari di apertura."), semantic()


def build_contract() -> list[dict]:
    from main import _json_safe  # noqa: E402
    cases = []
    for name, report, raw in scenarios():
        analysis = llm.apply_email_risk_policy(report, raw)
        (report.get("payment_details") or {}).pop("_body_ibans_raw", None)
        report = _json_safe({key: value for key, value in report.items()
                             if key not in {"raw_eml_bytes", "raw_eml_preview", "body_html", "html_preview"}})
        report["phi4_analysis"] = {"status": "ok", "analysis": _json_safe(analysis)}
        cases.append({"name": name, "python_verdict": analysis["final_verdict"], "report": report})
    return cases


class VerdictContractTests(unittest.TestCase):
    def test_contract_fixture_matches_the_current_policy(self):
        cases = build_contract()
        if os.getenv("FISHSTOP_WRITE_CONTRACT") == "1":
            FIXTURE.write_text(json.dumps(cases, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        stored = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(
            {case["name"]: case["python_verdict"] for case in cases},
            {case["name"]: case["python_verdict"] for case in stored},
            "Policy changed: regenerate test-fixtures/verdict-contract.json (see module docstring).",
        )

    def test_expected_python_verdicts(self):
        verdicts = {case["name"]: case["python_verdict"] for case in build_contract()}
        self.assertEqual("legitimate", verdicts["legitimate_order"])
        self.assertEqual("legitimate", verdicts["missing_dkim_only"])
        self.assertEqual("legitimate", verdicts["regular_invoice_iban"])
        self.assertEqual("phishing", verdicts["iban_change_foreign"])
        self.assertEqual("phishing", verdicts["personalised_login_link"])
        for name in ("cross_domain_reply_to", "masked_brand_link", "fabricated_thread", "svg_script",
                     "executable_attachment", "sender_lookalike", "ai_grounded_phishing"):
            self.assertEqual("phishing", verdicts[name], name)
        for name in ("fake_reply", "ipfs_link", "calendar_invite"):
            self.assertEqual("review", verdicts[name], name)


if __name__ == "__main__":
    unittest.main()
