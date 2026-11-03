"""Point 8: rendering-only MIME differences must not add prompt noise.

When the plain and HTML parts differ only by written-out URLs or an
HTML-only footer/navigation bar, the AI should see one version without
"[HTML alternative ...]" annotations and a second copy of the footer.
Any wording difference keeps the conservative merge.
"""

import sys
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fishstop_engine.analyzer.essential_text import merge_mime_alternatives

BODY = (
    "Gentile cliente,\n\n"
    "la tua fattura di ottobre è disponibile nell'area clienti.\n\n"
    "L'importo verrà addebitato sul metodo di pagamento registrato il 15 novembre.\n\n"
    "Grazie per aver scelto il nostro servizio."
)
MARKERS = ("alternative]", "alternative;", "omits passages", "Shared paragraphs omitted")


class LinksOrFooterOnlyTests(unittest.TestCase):
    def _assert_single(self, primary, alternative):
        merged, stats = merge_mime_alternatives(primary, alternative)
        self.assertEqual(primary, merged)
        self.assertFalse(stats["alternatives_differ"])
        self.assertEqual("links_or_footer_only", stats.get("alternative_difference"))

    def test_urls_written_out_in_the_plain_part(self):
        plain = BODY.replace("area clienti.", "area clienti <https://www.esempio.it/area?utm=1>.")
        self._assert_single(plain, BODY)
        self._assert_single(BODY, plain)

    def test_changed_tracking_url_only(self):
        a = BODY + "\n\nhttps://t.esempio.it/c/AAA"
        b = BODY + "\n\nhttps://t.esempio.it/c/BBB"
        self._assert_single(a, b)

    def test_html_only_footer(self):
        html = BODY + (
            "\n\nAnnulla l'iscrizione | Informativa privacy | Gestisci le preferenze\n"
            "© 2026 Esempio S.p.A. - Sede legale Via Roma 1, Milano - P.IVA 01234567890"
        )
        self._assert_single(BODY, html)

    def test_html_only_navigation_bar(self):
        self._assert_single(BODY, BODY + "\n\nHome | Prodotti | Contatti\nSeguici su Instagram")

    def test_english_footer(self):
        html = BODY + "\n\nYou are receiving this email because you subscribed.\nUnsubscribe · Privacy Policy\nACME Ltd, 1 High Street, London"
        self._assert_single(BODY, html)


class WordingDifferencesStayVisibleTests(unittest.TestCase):
    def _assert_merged(self, primary, alternative, must_contain):
        merged, stats = merge_mime_alternatives(primary, alternative)
        self.assertTrue(stats["alternatives_differ"])
        self.assertIn(must_contain, merged)
        self.assertTrue(any(marker in merged for marker in MARKERS), merged)

    def test_html_only_lure_at_the_end(self):
        lure = "Il tuo account verrà sospeso: verifica subito i tuoi dati."
        self._assert_merged(BODY, BODY + "\n\n" + lure, lure)

    def test_lure_disguised_among_footer_words(self):
        lure = "Informativa privacy: conferma la password entro oggi."
        self._assert_merged(BODY, BODY + "\n\nAnnulla l'iscrizione\n" + lure, lure)

    def test_extra_sentence_in_the_middle(self):
        extra = "Nota: il conto di addebito è cambiato."
        html = BODY.replace("Grazie per", extra + "\n\nGrazie per")
        self._assert_merged(BODY, html, extra)

    def test_negation_change(self):
        html = BODY.replace("verrà addebitato", "non verrà addebitato")
        self._assert_merged(BODY, html, "non verrà addebitato")

    def test_destination_and_wording_change_together(self):
        plain = BODY + "\n\nDo not pay. https://example.test/original"
        html = BODY + "\n\nPay now. https://example.test/replacement"
        self._assert_merged(plain, html, "Pay now.")


class AnalyzerIntegrationTests(unittest.TestCase):
    def test_footer_only_html_reaches_the_ai_once(self):
        from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer
        message = EmailMessage()
        message["From"] = "Esempio <fatture@esempio.it>"
        message["To"] = "cliente@example.com"
        message["Subject"] = "Fattura di ottobre"
        message.set_content(BODY)
        html_body = "".join(f"<p>{p}</p>" for p in BODY.split("\n\n"))
        html_body += ('<p><a href="https://www.esempio.it/unsub">Annulla l\'iscrizione</a> | '
                      '<a href="https://www.esempio.it/privacy">Informativa privacy</a></p>'
                      "<p>© 2026 Esempio S.p.A. - P.IVA 01234567890</p>")
        message.add_alternative(f"<html><body>{html_body}</body></html>", subtype="html")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "invoice.eml"
            path.write_bytes(bytes(message))
            report = EmlSOCAnalyzer().analyze(str(path))
        self.assertIn("fattura di ottobre è disponibile", report["body_for_ai"])
        self.assertFalse(any(marker in report["body_for_ai"] for marker in MARKERS), report["body_for_ai"])
        self.assertFalse(report["body_alternatives_divergent"])


if __name__ == "__main__":
    unittest.main()
