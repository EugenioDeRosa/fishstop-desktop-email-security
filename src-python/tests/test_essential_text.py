import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path

from fishstop_engine.analyzer.essential_text import (
    compact_repeated_blocks,
    merge_mime_alternatives,
    without_compaction_notices,
)
from fishstop_engine.analyzer import llm_context_analyzer as llm
from fishstop_engine.analyzer.soc_analyzer import EmlSOCAnalyzer


def layout_block():
    return "\n".join((f"Article {i}: " + "ordinary newsletter content " * 8).rstrip()
                     for i in range(4))


class EssentialTextTests(unittest.TestCase):
    def test_long_exact_repeat_preserves_first_copy_and_unique_request(self):
        block = layout_block()
        request = "Instead transfer EUR 123.45 to GB001 and visit https://example.test/a?token=secret"
        original = block + "\n" + request + "\n" + block
        compacted, stats = compact_repeated_blocks(original)
        self.assertEqual(1, compacted.count(block))
        self.assertIn(request, compacted)
        self.assertEqual(1, stats['duplicate_blocks'])
        self.assertLess(len(compacted), len(original))
        self.assertEqual(compacted, compact_repeated_blocks(compacted)[0])

    def test_similar_commands_are_never_fuzzily_removed(self):
        first = layout_block() + "\nPay EUR 100 using https://example.test/?account=one"
        second = layout_block() + "\nDo not pay EUR 900 using https://example.test/?account=two"
        compacted, _ = compact_repeated_blocks(first + "\n" + second)
        self.assertIn("Pay EUR 100 using https://example.test/?account=one", compacted)
        self.assertIn("Do not pay EUR 900 using https://example.test/?account=two", compacted)

    def test_short_repeated_password_fields_are_preserved(self):
        text = "Password: abc123\nPassword: abc123\nPay now\nPay now"
        self.assertEqual(text, compact_repeated_blocks(text)[0])

    def test_turn_boundaries_preserve_each_senders_identical_request(self):
        for boundary in ("From: second@example.test", "On Tuesday someone wrote:",
                         "[TARGET MESSAGE 2]", "---------- Forwarded message ---------"):
            with self.subTest(boundary=boundary):
                text = layout_block() + "\n" + boundary + "\n" + layout_block()
                self.assertEqual(text, compact_repeated_blocks(text)[0])

    def test_mime_equivalent_layout_is_only_sent_once(self):
        plain = "Hello customer\nRead the report"
        merged, stats = merge_mime_alternatives(plain, "Hello   customer\n\nRead the report")
        self.assertEqual(plain, merged)
        self.assertFalse(stats['alternatives_differ'])

    def test_mime_unique_negation_and_destinations_survive(self):
        shared = [f"Paragraph {i}: " + "general information " * 12 for i in range(10)]
        plain = "\n\n".join(shared + ["Do not pay. https://example.test/original"])
        html = "\n\n".join(shared + ["Pay now. https://example.test/replacement?token=private"])
        merged, stats = merge_mime_alternatives(plain, html)
        self.assertIn("Do not pay. https://example.test/original", merged)
        self.assertIn("Pay now. https://example.test/replacement?token=private", merged)
        self.assertGreater(stats['alternative_characters_omitted'], 0)
        self.assertLess(len(merged), len(plain) + len(html))

    def test_mime_deletion_and_reordering_are_visible(self):
        shared = [f"Paragraph {i}: " + "general information " * 12 for i in range(10)]
        plain = "\n\n".join(shared[:5] + ["Do not transfer funds."] + shared[5:])
        html = "\n\n".join(shared)
        merged, _ = merge_mime_alternatives(plain, html)
        self.assertIn("Do not transfer funds.", merged)
        self.assertIn("omits passages", merged)
        reordered = shared[:4] + [shared[5], shared[4]] + shared[6:]
        merged, _ = merge_mime_alternatives("\n\n".join(shared), "\n\n".join(reordered))
        alternative = merged.split("[HTML alternative", 1)[1]
        self.assertIn(shared[5], alternative)
        self.assertIn(shared[4], alternative)

    def test_short_alternatives_are_not_inflated_by_annotations(self):
        merged, stats = merge_mime_alternatives("Do not pay.", "Pay now.")
        self.assertEqual("Do not pay.\n\n[HTML alternative]\nPay now.", merged)
        self.assertEqual(0, stats['alternative_characters_omitted'])

    def test_disjoint_mime_changes_keep_an_explicit_gap(self):
        shared = [f"Paragraph {i}: " + "general information " * 12 for i in range(18)]
        alternative = shared.copy()
        alternative[2] = 'A changed destination: https://example.test/one'
        alternative[15] = 'A second changed destination: https://example.test/two'
        merged, _ = merge_mime_alternatives('\n\n'.join(shared), '\n\n'.join(alternative))
        self.assertIn('Shared paragraphs omitted here', merged)
        self.assertIn(alternative[2], merged)
        self.assertIn(alternative[15], merged)
        self.assertNotIn('Shared paragraphs omitted here', without_compaction_notices(merged))

    def test_parser_annotations_cannot_ground_email_evidence_or_identity(self):
        compacted, _ = compact_repeated_blocks(layout_block() + "\n" + layout_block())
        marker = next(line for line in compacted.splitlines() if line.startswith("[Repeated"))
        soc = {'body_for_ai': compacted, 'body_for_identity': compacted}
        self.assertEqual('', llm._validated_evidence(soc, marker))
        self.assertEqual('', llm._validated_evidence(soc, marker, 'context'))
        self.assertNotIn(marker, llm._message_evidence_text(soc))
        self.assertNotIn(marker, llm._identity_body_text(soc))
        self.assertTrue(llm._validated_evidence(soc, 'ordinary newsletter content'))

    def test_integration_keeps_originals_links_attachment_and_signature(self):
        message = EmailMessage()
        message['From'] = 'Finance <finance@example.test>'
        message['To'] = 'recipient@example.net'
        message['Subject'] = 'Report and payment details'
        block = layout_block()
        message.set_content(block + '\n' + block + '\n'
                            'Open https://example.test/report?token=private\n\n'
                            'Kind regards,\nFinance Example Company\nfinance@example.test')
        message.add_attachment(b'reference details', maintype='application',
                               subtype='octet-stream', filename='reference.bin')
        raw = message.as_bytes()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'sample.eml'
            path.write_bytes(raw)
            report = EmlSOCAnalyzer().analyze(str(path))
        self.assertEqual(raw, report['raw_eml_bytes'])
        self.assertEqual(2, report['body_clean'].count(block))
        self.assertEqual(1, report['body_for_ai'].count(block))
        self.assertIn('Finance Example Company', report['body_for_identity'])
        self.assertTrue(any(link['url'] == 'https://example.test/report?token=private'
                            for link in report['links']))
        self.assertEqual('reference.bin', report['attachments'][0]['filename'])
        self.assertEqual(1, report['ai_text_compaction']['body']['duplicate_blocks'])


if __name__ == '__main__':
    unittest.main()
