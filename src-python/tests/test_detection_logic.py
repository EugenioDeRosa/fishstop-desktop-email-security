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


if __name__ == "__main__":
    unittest.main()
