"""Regression tests for static detection logic (lookalikes, masked links,
active attachments and reply routing). All messages are synthetic."""
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.analyzer.lookalike import check_lookalike_domains
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
from fishstop_engine.domain_utils import registered_domain

BENIGN_LINK = {"summary": "Ordinary notice.", "action": "visit_link", "channel": "link",
               "evidence": "", "signals": [], "ambiguity": "low", "risk_assessment": "benign",
               "risk_evidence": "", "risk_rationale": "Ordinary notice."}


def analyze(sender, subject="Notice", *, html=None, text="See the HTML version.", reply_to=None,
            to="mario.rossi@azienda.it", attachments=(), headers=None):
    message = EmailMessage()
    message["From"] = sender
    message["To"] = to
    message["Subject"] = subject
    message["Date"] = "Mon, 26 Oct 2026 10:00:00 +0000"
    message["Message-ID"] = "<synthetic@fishstop.invalid>"
    if reply_to:
        message["Reply-To"] = reply_to
    for name, value in (headers or {}).items():
        message[name] = value
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    for filename, content_type, payload in attachments:
        maintype, subtype = content_type.split("/")
        message.add_attachment(payload, maintype=maintype, subtype=subtype, filename=filename)
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "message.eml"
        path.write_bytes(bytes(message))
        report = EmlSOCAnalyzer().analyze(str(path))
    report.setdefault("body_for_ai", report.get("body_ai") or report.get("body_clean") or "")
    return report


def flags(report, field=None, levels=("HIGH", "MEDIUM")):
    return [flag for flag in report["flags"]
            if flag["level"] in levels and (field is None or flag["field"] == field)]


def alerts_for(host, **kwargs):
    return check_lookalike_domains([{"host": host, "url": f"https://{host}/"}], **kwargs)


class PublicSuffixTests(unittest.TestCase):
    def test_shared_hosting_tenants_are_separate_registrable_domains(self):
        for host in ("evil.pages.dev", "evil.vercel.app", "evil.netlify.app", "pub-x.r2.dev",
                     "evil.ngrok-free.app", "evil.github.io"):
            with self.subTest(host=host):
                self.assertEqual(host, registered_domain(host))
        self.assertEqual("paypal.com", registered_domain("mail.paypal.com"))
        self.assertEqual("bbc.co.uk", registered_domain("www.bbc.co.uk"))
        self.assertEqual("evil.example", registered_domain("evil.example"))

    def test_masked_link_between_tenants_of_the_same_platform(self):
        report = analyze("IT <it@corp-it.example>", html=(
            '<p><a href="https://m1cr0soft-login.pages.dev/auth">https://microsoft-sso.pages.dev/auth</a></p>'))
        link = next(link for link in report["links"] if "m1cr0soft" in link["url"])
        self.assertTrue(link["display_mismatch"])


class LookalikeTests(unittest.TestCase):
    def test_ordinary_words_and_official_domains_are_not_brand_lookalikes(self):
        for host in ("like.com", "line.me", "olive.com", "email.com", "ample.com", "maple.com",
                     "chose.com", "phase.com", "cloud.com", "posta.com", "paste.com", "pineapple.com",
                     "startups-online.com", "amazon.de", "apple.co.uk", "microsoftonline.com",
                     "login.microsoftonline.com", "amazon-adsystem.com", "dropboxusercontent.com"):
            with self.subTest(host=host):
                self.assertEqual([], alerts_for(host))

    def test_typosquatting_and_confusable_substitutions(self):
        for host in ("paypa1.com", "rnicrosoft.com", "arnazon.com", "g00gle.com", "micros0ft.com",
                     "goolge.com", "paypall.com", "pay-pal.com", "netfiix.com", "linkedln.com", "fedexx.com"):
            with self.subTest(host=host):
                self.assertTrue(any(alert["level"] == "HIGH" for alert in alerts_for(host)))

    def test_combosquatting_and_official_domain_as_subdomain(self):
        high = ("paypal-security.com", "secure-paypal-login.com", "paypalsecure.com", "amazon-verify.net",
                "intesa-sanpaolo-sicurezza.com", "poste-italiane.info", "posteitaliane-verifica.com",
                "unicredit-online.net", "ups-tracking.com", "paypal-verify.pages.dev",
                "paypal.com.account-check.ru", "login.microsoftonline.com.evil.xyz")
        for host in high:
            with self.subTest(host=host):
                self.assertTrue(any(alert["level"] == "HIGH" for alert in alerts_for(host)), alerts_for(host))
        for host in ("paypal.evil.ru", "dhl-express.info"):
            with self.subTest(host=host):
                self.assertEqual(["MEDIUM"], [alert["level"] for alert in alerts_for(host)])

    def test_brand_in_tenant_subdomain(self):
        # Known SaaS platforms and brand-operated domains host organisation tenants.
        self.assertEqual([], alerts_for("zalando-help.zendesk.com", known_brands=["zalando.it"]))
        self.assertEqual([], alerts_for("azienda.sharepoint.com", known_brands=["azienda.it"]))
        # Elsewhere a protected name in the subdomain is capped at review.
        self.assertEqual(["MEDIUM"], [a["level"] for a in alerts_for("zalando-help.unknown-host.com", known_brands=["zalando.it"])])

    def test_one_alert_per_brand(self):
        self.assertEqual(1, len(alerts_for("microsoft-support-team.com")))

    def test_sender_domain_lookalike_without_links(self):
        report = analyze("Fatturazione <amministrazione@paypa1.com>", text="Nuovo IBAN, rispondere per conferma.")
        self.assertEqual(["HIGH"], [flag["level"] for flag in flags(report, "Sender lookalike")])
        status, reasons = llm._technical_risk(report)
        self.assertEqual("malicious", status)

    def test_recipient_organisation_domain_is_protected(self):
        report = analyze("CEO <ceo@azienda-spa.it>", text="Bonifico urgente.", to="mario.rossi@azienda.it")
        self.assertTrue(flags(report, "Sender lookalike"))
        internal = analyze("CEO <ceo@azienda.it>", text="Riunione alle 10.", to="mario.rossi@azienda.it")
        self.assertFalse(flags(internal, "Sender lookalike"))
        freemail = analyze("Mario <mario@gmail.com>", text="Ciao", to="anna@azienda.it")
        self.assertFalse(flags(freemail, "Sender lookalike"))
        tenant = analyze("Anna <anna@azienda.it>", to="mario.rossi@azienda.it",
                         html='<a href="https://azienda.sharepoint.com/sites/team">documento</a>')
        self.assertFalse(flags(tenant))

    def test_redirect_destination_is_checked(self):
        report = analyze("M365 <no-reply@alerts.example>", html=(
            '<a href="https://www.google.com/url?q=https://paypal-secure-login.example/x&sa=D">Open</a>'))
        link = report["links"][0]
        self.assertIn("paypal-secure-login.example", link["redirect_hosts"])
        self.assertTrue(any(alert["host"] == "paypal-secure-login.example" for alert in report["lookalike_alerts"]))


class MaskedAndUnsafeLinkTests(unittest.TestCase):
    def test_link_text_showing_a_brand_but_opening_another_host_is_high(self):
        report = analyze("Banca <avvisi@notifiche-banca.example>", html=(
            '<a href="https://account-check.example/login">https://www.intesasanpaolo.com/login</a>'))
        self.assertEqual(["HIGH"], [flag["level"] for flag in flags(report, "Masked link")])
        result = llm.apply_email_risk_policy(report, dict(BENIGN_LINK, evidence="login"))
        self.assertEqual("phishing", result["final_verdict"])

    def test_tracked_newsletter_link_is_not_reported(self):
        report = analyze("Shop <news@shop.example>", html=(
            '<a href="https://shop.us1.list-manage.com/track/click?id=1">www.shop.example</a>'))
        self.assertFalse(flags(report, "Masked link"))

    def test_other_masked_destination_requires_review(self):
        report = analyze("Shop <news@shop.example>", html='<a href="https://other.example/x">www.shop.example</a>')
        self.assertEqual(["MEDIUM"], [flag["level"] for flag in flags(report, "Masked link")])

    def test_javascript_and_data_links_are_high(self):
        for href in ("javascript:location='https://evil.example'", "data:text/html;base64,PHNjcmlwdD4=",
                     "  JaVaScRiPt:void(0)"):
            with self.subTest(href=href):
                report = analyze("Admin <admin@it.example>", html=f'<a href="{href}">Apri</a>')
                self.assertTrue(report["unsafe_scheme_links"])
                self.assertTrue(any("javascript" in flag["message"] or "data:" in flag["message"]
                                    for flag in flags(report, "Link", ("HIGH",))))

    def test_area_meta_refresh_and_onclick_destinations_are_extracted(self):
        report = analyze("IT <it@it.example>", html=(
            '<html><head><meta http-equiv="refresh" content="0;url=https://refresh.example/"></head><body>'
            '<map name="m"><area href="https://area.example/a" coords="0,0,1,1"></map>'
            '<div onclick="location=\'https://onclick.example/\'">Clicca</div></body></html>'))
        hosts = {link["host"] for link in report["links"]}
        self.assertTrue({"refresh.example", "area.example", "onclick.example"} <= hosts)


class ActiveAttachmentTests(unittest.TestCase):
    def html_security(self, filename, content_type, payload):
        report = analyze("Docs <docs@docs.example>", text="Allegato.", attachments=[(filename, content_type, payload)])
        return report, report["attachments"][0].get("html_security") or {}

    def test_svg_with_script_is_high(self):
        report, security = self.html_security("VM_0042.svg", "image/svg+xml",
            b'<svg xmlns="http://www.w3.org/2000/svg"><script>window.location="https://evil.example/"</script></svg>')
        self.assertEqual("high", security["risk_level"])
        self.assertIn("svg_active_content", {item["key"] for item in security["findings"]})
        self.assertEqual("malicious", llm._technical_risk(report)[0])

    def test_html_obfuscated_redirect_and_smuggling_are_high(self):
        _, redirect = self.html_security("Documento.htm", "text/html",
            b'<html><script>location.href=atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGU=")</script></html>')
        self.assertEqual("high", redirect["risk_level"])
        payload = b"A" * 25000
        _, smuggling = self.html_security("Invoice.html", "text/html",
            b'<html><script>var d="' + payload + b'";var b=new Blob([Uint8Array.from(atob(d))]);'
            b'var a=document.createElement("a");a.href=URL.createObjectURL(b);a.download="inv.iso";a.click()</script></html>')
        self.assertIn("html_smuggling", {item["key"] for item in smuggling["findings"]})
        _, refresh = self.html_security("Avviso.html", "text/html",
            b'<html><head><meta http-equiv="refresh" content="0; url=https://evil.example/"></head></html>')
        self.assertEqual("high", refresh["risk_level"])

    def test_plain_svg_and_static_html_remain_clean(self):
        _, svg = self.html_security("logo.svg", "image/svg+xml",
            b'<svg xmlns="http://www.w3.org/2000/svg"><circle r="4"/></svg>')
        self.assertEqual("clean", svg["risk_level"])
        _, html = self.html_security("Programma.html", "text/html", b"<html><body><p>Agenda</p></body></html>")
        self.assertEqual("clean", html["risk_level"])

    def test_onenote_attachment_is_high_risk(self):
        report = analyze("Docs <docs@docs.example>", text="Allegato.",
                         attachments=[("Fattura.one", "application/octet-stream", b"\xe4\x52\x5c\x7b" + b"\x00" * 64)])
        self.assertTrue(flags(report, "Attachment", ("HIGH",)))


class ReplyRoutingRegressionTests(unittest.TestCase):
    def test_cross_domain_reply_remains_a_strong_indicator(self):
        # Product policy: an unexplained Reply-To on another domain is HIGH,
        # also for newsletters claiming bulk headers.
        report = analyze("Newsletter <news@shop.example>", reply_to="care@shop-help.zendesk.com",
                         html='<a href="https://www.shop.example/new">Nuovi arrivi</a>',
                         headers={"List-Unsubscribe": "<https://shop.example/unsub>"})
        self.assertEqual("HIGH", report["reply_to_routing"]["level"])
        self.assertEqual("malicious", llm._technical_risk(report)[0])

    def test_lookalike_reply_domain_is_also_reported_as_sender_lookalike(self):
        report = analyze("Accounts <accounts@paypal.com>", reply_to="support@paypal-help-desk.com",
                         text="Rispondi per confermare.")
        self.assertEqual("HIGH", report["reply_to_routing"]["level"])
        self.assertTrue(any(alert["field"] == "Reply-To" for alert in report["sender_lookalike_alerts"]))


QUOTED_FROM_RECIPIENT = (
    "Ciao Mario, come d'accordo procedi con il bonifico sul nuovo IBAN entro oggi.\n\n"
    "Da: Mario Rossi <mario.rossi@azienda.it>\n"
    "Inviato: lunedì 26 ottobre 2026 09:12\n"
    "A: Luca Bianchi <luca@fornitore.example>\n"
    "Oggetto: Fattura 2026/118\n\n"
    "Buongiorno, attendo le nuove coordinate per il pagamento.\n"
)
QUOTED_THIRD_PARTY = (
    "Vedi sotto, serve conferma.\n\n"
    "Da: Giulia Verdi <giulia@partner.example>\n"
    "Inviato: lunedì 26 ottobre 2026 09:12\n"
    "A: Luca Bianchi <luca@fornitore.example>\n"
    "Oggetto: Ordine\n\n"
    "Confermo l'ordine.\n"
)


class FakeReplyTests(unittest.TestCase):
    def test_reply_prefix_without_threading_headers_requires_review(self):
        for subject in ("RE: Fattura 2026/118", "R: pagamento", "[EXT] Re: ordine", "AW: Rechnung", "RE[2]: contratto"):
            with self.subTest(subject=subject):
                report = analyze("Luca <luca@fornitore.example>", subject, text="Ti allego il documento.")
                self.assertEqual("MEDIUM", report["reply_threading"]["level"])
                self.assertTrue(flags(report, "Reply thread"))
                self.assertEqual("uncertain", llm._technical_risk(report)[0])

    def test_genuine_replies_are_not_reported(self):
        for headers in ({"In-Reply-To": "<a1@fornitore.example>"},
                        {"References": "<a1@fornitore.example> <a2@azienda.it>"},
                        {"Thread-Index": "AQHZx1y2abcdEFGH"}):
            with self.subTest(headers=headers):
                report = analyze("Luca <luca@fornitore.example>", "RE: Fattura", text="Ok.", headers=headers)
                self.assertEqual("NONE", report["reply_threading"]["level"])
                self.assertFalse(flags(report, "Reply thread", ("HIGH", "MEDIUM", "LOW")))

    def test_non_reply_subjects_are_ignored(self):
        for subject in ("Fattura RE: 2026", "Regolamento", "Riunione", "FW: documento", "Rif. ordine 12"):
            with self.subTest(subject=subject):
                report = analyze("Luca <luca@fornitore.example>", subject, text="Testo.")
                self.assertEqual("NONE", report["reply_threading"]["level"])

    def test_fabricated_history_attributed_to_the_recipient_is_high(self):
        report = analyze("Luca <luca@fornitore-amministrazione.example>", "RE: Fattura 2026/118",
                         text=QUOTED_FROM_RECIPIENT, to="mario.rossi@azienda.it")
        threading = report["reply_threading"]
        self.assertEqual("HIGH", threading["level"])
        self.assertTrue(threading["quoted_from_recipient"])
        self.assertEqual("malicious", llm._technical_risk(report)[0])

    def test_fabricated_third_party_history_is_review_unless_sensitive(self):
        report = analyze("Luca <luca@fornitore.example>", "RE: Ordine", text=QUOTED_THIRD_PARTY)
        self.assertEqual("MEDIUM", report["reply_threading"]["level"])
        self.assertEqual("uncertain", llm._technical_risk(report)[0])
        self.assertEqual("malicious", llm._technical_risk(report, {"asks_for_payment": True})[0])

    def test_bulk_sender_fake_reply_is_low(self):
        report = analyze("Shop <news@shop.example>", "RE: la tua offerta", text="Sconti.", headers={
            "List-Unsubscribe": "<https://shop.example/u>", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
            "Precedence": "bulk", "List-Id": "<news.shop.example>", "Feedback-ID": "1:2:3:shop"})
        self.assertIn(report["reply_threading"]["level"], {"LOW", "MEDIUM"})
        if report["is_bulk_sender"]:
            self.assertEqual("LOW", report["reply_threading"]["level"])


class PaymentDetailsTests(unittest.TestCase):
    IBAN_IT = "IT60 X054 2811 1010 0000 0123 456"
    IBAN_LT = "LT12 1000 0111 0100 1000"

    def levels(self, report, key):
        return [a["level"] for a in report["payment_details"]["alerts"] if a["key"] == key]

    def test_iban_validation_rejects_wrong_checksums_and_lengths(self):
        from fishstop_engine.analyzer.payment_details import extract_ibans, mask_iban
        self.assertEqual(["IT60X0542811101000000123456"], extract_ibans(f"IBAN {self.IBAN_IT} BIC BPMOIT22"))
        self.assertEqual([], extract_ibans("IT60X0542811101000000123457 IT60X054281110100000012345"))
        self.assertEqual("IT60 **** 3456", mask_iban("IT60X0542811101000000123456"))

    def test_change_request_with_foreign_account_is_high(self):
        report = analyze("Fornitore <amministrazione@fornitore.it>", "Coordinate",
                         text=f"Vi comunichiamo le nuove coordinate bancarie: {self.IBAN_LT}.")
        self.assertEqual(["HIGH"], self.levels(report, "iban_change_request"))
        self.assertTrue(flags(report, "Payment details", ("HIGH",)))
        self.assertNotIn("1000 0111", " ".join(f["message"] for f in report["flags"]))

    def test_change_request_with_domestic_account_is_review(self):
        report = analyze("Fornitore <amministrazione@fornitore.it>", "Coordinate",
                         text=f"Abbiamo cambiato banca, nuovo IBAN {self.IBAN_IT}.")
        self.assertEqual(["MEDIUM"], self.levels(report, "iban_change_request"))

    def test_iban_changed_inside_the_conversation_is_high(self):
        text = (f"Buongiorno, per errore vi avevamo indicato il conto sotto. Pagate su {self.IBAN_LT}.\n\n"
                "Da: Luca Bianchi <luca@fornitore.it>\nInviato: lunedì 26 ottobre 2026 09:12\n"
                "A: Mario Rossi <mario.rossi@azienda.it>\nOggetto: Fattura\n\n"
                f"In allegato la fattura, IBAN {self.IBAN_IT}.\n")
        report = analyze("Luca <luca@fornitore.it>", "RE: Fattura", text=text,
                         headers={"In-Reply-To": "<a@fornitore.it>"})
        self.assertEqual(["HIGH"], self.levels(report, "iban_changed_in_thread"))

    def test_invoice_without_change_is_not_reported(self):
        report = analyze("Fornitore <amministrazione@fornitore.it>", "Fattura 118",
                         text=f"In allegato la fattura. Pagamento su IBAN {self.IBAN_IT} come sempre.")
        self.assertEqual([], report["payment_details"]["alerts"])

    def test_local_memory_reports_a_new_account_for_a_known_sender(self):
        import os
        from fishstop_engine.analyzer.payment_details import apply_payment_memory, assess_payment_details
        with tempfile.TemporaryDirectory() as directory:
            previous = os.environ.get("FISHSTOP_IDENTITY_DATA_DIR")
            os.environ["FISHSTOP_IDENTITY_DATA_DIR"] = directory
            try:
                first = analyze("Fornitore <amministrazione@fornitore.it>", "Fattura", text=f"IBAN {self.IBAN_IT}.")
                self.assertEqual([], apply_payment_memory(first, "message-1"))
                again = analyze("Fornitore <amministrazione@fornitore.it>", "Fattura", text=f"IBAN {self.IBAN_IT}.")
                self.assertEqual([], apply_payment_memory(again, "message-2"))
                changed = analyze("Fornitore <amministrazione@fornitore.it>", "Fattura", text=f"Pagare su {self.IBAN_LT}.")
                self.assertEqual(["MEDIUM"], [a["level"] for a in apply_payment_memory(changed, "message-3")])
                reanalysed = analyze("Fornitore <amministrazione@fornitore.it>", "Fattura", text=f"Pagare su {self.IBAN_LT}.")
                self.assertEqual(["MEDIUM"], [a["level"] for a in apply_payment_memory(reanalysed, "message-3")])
                self.assertNotIn("_body_ibans_raw", changed["payment_details"])
                stored = (Path(directory) / "payment-memory.sqlite").read_bytes()
                self.assertNotIn(b"IT60X0542811101000000123456", stored)
            finally:
                if previous is None:
                    os.environ.pop("FISHSTOP_IDENTITY_DATA_DIR", None)
                else:
                    os.environ["FISHSTOP_IDENTITY_DATA_DIR"] = previous


class LinkDomainAgeTests(unittest.TestCase):
    @staticmethod
    def observation(days):
        import datetime
        date = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat()
        return {"status": "observed", "events": [{"action": "registration", "date": date}]}

    def run_age(self, report, ages, disabled=frozenset()):
        from fishstop_engine.analyzer.link_domain_age import apply_link_domain_age
        queried = []
        def lookup(domain):
            queried.append(domain)
            return self.observation(ages.get(domain, 3000))
        apply_link_domain_age(report, set(disabled), lookup)
        return queried

    def test_new_and_recent_link_domains(self):
        report = analyze("Team <team@service.example.com>", html=(
            '<a class="btn" href="https://fresh-login.com/x">Accedi</a> <a href="https://recent-shop.com/">x</a>'
            ' <a href="https://www.paypal.com/x">PayPal</a> <a href="https://tenant.pages.dev/">t</a>'))
        queried = self.run_age(report, {"fresh-login.com": 2, "recent-shop.com": 20})
        self.assertEqual({"fresh-login.com", "recent-shop.com"}, set(queried))
        self.assertEqual({"HIGH", "MEDIUM"}, {f["level"] for f in flags(report, "Link domain age")})

    def test_disabled_in_local_only(self):
        report = analyze("Team <team@service.example.com>", html='<a href="https://fresh-login.com/x">x</a>')
        self.assertEqual([], self.run_age(report, {"fresh-login.com": 1}, {"local_only"}))
        self.assertFalse(flags(report, "Link domain age"))


class LinkHostingTests(unittest.TestCase):
    def test_ipfs_is_review_and_shortener_only_as_call_to_action(self):
        report = analyze("Docs <docs@docs.example>", html=(
            '<a href="https://ipfs.io/ipfs/bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi">Apri</a>'
            '<a href="https://bit.ly/abc">dettagli</a>'))
        levels = {a["kind"]: a["level"] for a in report["link_hosting_alerts"]}
        self.assertEqual({"ipfs": "MEDIUM", "shortener": "INFO"}, levels)
        button = analyze("Docs <docs@docs.example>", html='<a class="button" href="https://bit.ly/abc">Paga ora</a>')
        self.assertEqual(["MEDIUM"], [a["level"] for a in button["link_hosting_alerts"]])

    def test_recipient_address_in_link(self):
        import base64
        encoded = base64.b64encode(b"mario.rossi@azienda.it").decode()
        report = analyze("IT <it@it.example>", html=(
            '<a href="https://login.example.com/#mario.rossi@azienda.it">Accedi</a>'
            f'<a href="https://portal.example.com/?u={encoded}">Portale</a>'
            '<a href="https://news.example.com/unsubscribe?email=mario.rossi@azienda.it">Disiscriviti</a>'))
        levels = sorted(a["level"] for a in report["recipient_link_alerts"])
        self.assertEqual(["HIGH", "MEDIUM"], levels)


class CalendarInviteTests(unittest.TestCase):
    ICS = ("BEGIN:VCALENDAR\r\nMETHOD:REQUEST\r\nBEGIN:VEVENT\r\nSUMMARY:Verifica account\r\n"
           "ORGANIZER;CN=IT:mailto:it@other-org.example\r\nATTENDEE:mailto:mario.rossi@azienda.it\r\n"
           "DESCRIPTION:La password scade. Accedi qui https://portal.other-org.example/lo\r\n gin entro oggi\r\n"
           "END:VEVENT\r\nEND:VCALENDAR\r\n")

    def test_invite_links_enter_the_link_pipeline(self):
        report = analyze("IT <it@company.example>", "Invito", text="Invito.",
                         attachments=[("invite.ics", "text/calendar", self.ICS.encode())])
        urls = {link["url"] for link in report["links"]}
        self.assertIn("https://portal.other-org.example/login", urls)
        self.assertEqual(["MEDIUM"], [f["level"] for f in flags(report, "Calendar invite")])

    def test_inline_calendar_part_and_matching_organizer(self):
        message = EmailMessage()
        message["From"] = "IT <it@other-org.example>"
        message["To"] = "mario.rossi@azienda.it"
        message["Subject"] = "Riunione"
        message.set_content("Riunione")
        message.add_alternative(self.ICS, subtype="calendar")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "invite.eml"
            path.write_bytes(bytes(message))
            report = EmlSOCAnalyzer().analyze(str(path))
        self.assertEqual(1, len(report["calendar_invites"]))
        self.assertTrue(any(link.get("source") == "calendar" for link in report["links"]))
        self.assertEqual(["INFO"], [a["level"] for a in report["calendar_alerts"]])


if __name__ == "__main__":
    unittest.main()
