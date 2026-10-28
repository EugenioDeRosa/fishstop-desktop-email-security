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

Unchanged product policy: a Reply-To on another mailbox without a recognised,
authenticated sharing or notification routing is HIGH. In addition, a reply
domain that imitates a protected brand or the recipient organisation is
reported as a `Sender lookalike` finding on the Reply-To field.

## Fake replies

A subject with a reply prefix (`RE:`, `R:`, `AW:`, `SV:`, `VS:`, `RIF:`,
`RES:`, also after tags such as `[EXT]` and with counters such as `RE[2]:`)
is compared with the delivered message's threading headers (`In-Reply-To`,
`References`, Outlook `Thread-Index`). Forward prefixes are not replies.

| Situation | Level |
|---|---|
| Threading header present, or no reply prefix | none |
| Bulk sender, reply prefix, no threading header | LOW |
| Reply prefix, no threading header | MEDIUM |
| As above, with a quoted history from third parties | MEDIUM |
| As above, with a quoted message attributed to the recipient or the recipient organisation | HIGH |

HIGH makes the technical axis malicious. MEDIUM is suspicious, and becomes
malicious when the semantic analysis grounds a payment, credential,
sensitive-data, settings-change or procedure-bypass request (typical BEC).
The check is skipped when an embedded forwarded message is the selected
target, because the threading headers belong to the outer message.

Limit: an EML exported by a tool that drops threading headers makes a genuine
reply look unthreaded. Gmail, Outlook, Apple Mail and Thunderbird keep them in
the original message source.

## Bank details (IBAN)

IBANs are extracted from the new message text, the quoted conversation and
attachment text (PDF/HTML), and validated by country length and mod-97
checksum. Reports and flags show only masked values (`IT60 **** 3456`).

| Situation | Level |
|---|---|
| New text gives an IBAN different from the quoted conversation | HIGH |
| Body IBAN differs from the attached document | HIGH |
| Change announcement ("nuove coordinate", "new bank details"...) + IBAN from another country than the sender ccTLD | HIGH |
| Change announcement + IBAN | MEDIUM |
| IBAN from another country, no change announcement | LOW |
| IBAN differs from accounts previously seen from the same sender domain on this device | MEDIUM (HIGH with a change announcement) |

The local memory (`payment-memory.sqlite` in the identity data directory)
keeps only salted SHA-256 digests per sender domain for two years. It can only
raise alerts: an account seen before never lowers the risk, so an earlier
harmless message cannot whitelist an attacker's account. Re-analysing the
same message gives the same result.

## Link domain age

When RDAP is enabled (not in Local only), the registry RDAP record of up to
five link domains is checked with the cached IANA-bootstrapped lookup
(10 s total budget). Sender, catalog, tracking and SaaS domains and tenants
of private suffixes (evil.pages.dev) are not queried. Registered less than
7 days ago: HIGH (MEDIUM for bulk senders); less than 30 days: MEDIUM.

## Link hosting and personalised links

`data/link-hosting.json` lists IPFS gateways, URL shorteners and free hosting
or form services. IPFS links are MEDIUM; shorteners and free hosting are
MEDIUM as a clickable call to action, informational otherwise. A link carrying
the recipient address in its fragment is HIGH, base64-encoded in path or query
MEDIUM (phishing kits pre-fill fake login pages this way). A plain address in
the query, typical of unsubscribe links, is not reported.

## Calendar invitations

`text/calendar` parts and `.ics` attachments are parsed (unfolded, bounded).
Links in the description, location, URL and attachments of events enter the
normal link pipeline (lookalike, masked links, reputation, domain age). An
event with links whose organiser does not match the sender is MEDIUM, except
for calendar services that send on behalf of an organiser. Files embedded in
the calendar data are MEDIUM. The event description is not yet included in the
local AI input.

## Single severity table

`data/signal-policy.json` assigns each finding an id, a category and a
verdict effect derived from its level: HIGH is decisive (technical axis
malicious, HIGH RISK), MEDIUM is supporting (uncertain, REVIEW), LOW/INFO are
informational. The interface filters (MIME diagnostics, outer-delivery checks
for a selected embedded message, Return-Path with DMARC pass, missing DKIM)
are applied identically. Reports carry `verdict_signals` and
`signal_policy_version`; the SIEM export uses the signal ids and effects.
`test-fixtures/verdict-contract.json` holds reports generated by the real
engine and policy; `scripts/test_verdict_contract.mjs` checks that the
interface reaches the same verdict for each of them.

## Known gaps

Callback (telephone) scams and brand display names on personal mailboxes are
not yet deterministic signals; encrypted archives with the password in the
message are reported only as incomplete inspection.
