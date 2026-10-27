# Static detection checks

These checks run without the local AI and without network access. They feed
both the SOC flags shown in the report and the technical axis of the semantic
policy (`_technical_risk`).

## Public Suffix List

Registrable domains use `publicsuffixlist`, which bundles a recent PSL snapshot
including private suffixes. Tenants of shared platforms (`*.pages.dev`,
`*.vercel.app`, `*.netlify.app`, `*.r2.dev`, `*.ngrok-free.app`) are separate
registrable domains, so a link showing one tenant and opening another is a
masked link. Unknown suffixes keep the complete host.

## Lookalike domains

Applied to actionable links, nested redirect destinations, and the From,
Reply-To and Return-Path domains. Protected names are the catalog in
`fishstop_engine/data/brand-lookalike.json` plus the recipient organisation.

| Technique | Example | Level |
|---|---|---|
| Confusable characters | `paypa1.com`, `rnicrosoft.com`, `g00gle.com` | HIGH |
| Typo-class edit (doubling, transposition, hyphen, confusable) | `paypall.com`, `goolge.com`, `pay-pal.com` | HIGH |
| Other single substitution, label ≥ 6 | `amazan.com` | MEDIUM |
| Brand token + lure word | `paypal-security.com`, `posteitaliane-verifica.com` | HIGH |
| Brand token alone | `dhl-express.info` | MEDIUM |
| Official domain used as subdomain | `paypal.com.account-check.ru` | HIGH |
| Brand only in a subdomain | `paypal.evil.ru` | MEDIUM |

Not reported: the brand label on another TLD (`amazon.de`), official domains in
the catalog, tenants of known SaaS platforms (`azienda.sharepoint.com`,
`brand.zendesk.com`), and ordinary words within edit distance of short brands
(`like.com`, `email.com`, `posta.com`). A HIGH From-domain lookalike makes the
technical axis malicious.

## Masked and unsafe links

- Link text showing a protected brand or the recipient organisation, opening an
  unrelated non-tracking host: HIGH (technical axis malicious).
- Link text showing another domain, opening a non-tracking host, or a tracking
  host masking a protected brand: MEDIUM. Ordinary tracked newsletter links
  (SendGrid, Mailchimp, Safe Links, ...) are not reported.
- `javascript:`, `vbscript:`, `data:` and `file:` targets on links, image maps,
  forms or frames: HIGH.
- `<area href>`, `meta refresh` and `onclick` navigation destinations are
  extracted as links. Open-redirect parameters include `q`, `r`, `out`, `go` and
  similar; their destinations are checked for lookalikes.

## Active HTML and SVG attachments

SVG files are inspected like HTML. Without executing anything, scripts and
handlers are classified: automatic redirect or meta refresh (HIGH), runtime
decoding/obfuscation (MEDIUM, HIGH with a redirect), HTML smuggling (HIGH),
data sent to Telegram/Discord/Slack (HIGH) or other remote calls (MEDIUM), any
other script (MEDIUM). An SVG with scripts or embedded HTML is HIGH. OneNote,
CHM, XLL, MSC, INF, SCT/WSC, CAB and shell/ClickOnce link formats are treated as
high-risk delivery formats.

## Reply-To routing

A different reply domain alone is a review signal, not a phishing conviction.

| Situation | Level |
|---|---|
| Same organisation, different mailbox | LOW |
| Authenticated bulk sender, helpdesk/CRM reply domain | LOW |
| Other domain | MEDIUM |
| Personal mailbox provider behind an authenticated organisation sender | MEDIUM |
| Personal mailbox provider behind an unauthenticated organisation sender | HIGH |
| Reply domain imitating the sender, the recipient organisation or a brand | HIGH |
| Sender failed explicit independent verification | HIGH |

The semantic policy additionally makes the technical axis malicious when a
grounded payment, credential or sensitive-data request asks for a reply to an
address outside the sender's organisation.

## Known gaps

Callback (telephone) scams, brand display names on personal mailboxes, URL
shorteners/IPFS, and the registration age of link domains are not yet
deterministic signals; they depend on the local AI and online checks.
