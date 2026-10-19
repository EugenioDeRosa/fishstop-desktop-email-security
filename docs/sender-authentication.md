# Sender identity and unavailable checks

Policy `semantic-policy-v45-identity-context` keeps these observations separate:

- SPF, DKIM and DMARC results reported in received headers.
- Independent cryptographic verification of an aligned DKIM signature on the
  original EML. `domain_authentication.method` is `independent_dkim`;
  `reason=signature_absent` means verification is unavailable, not failed.
  `spf_recalculated=false` explicitly states that this operation does not rerun SPF.
- Documented relationships between companies and domains, with an attributable
  source, scopes and expiry. These do not authenticate an individual message or
  authorize arbitrary credential, payment or account destinations.

Both frontend and backend use independent domain authentication when it is
present. Header-only fallbacks remain for historical reports that do not contain
that field. For a sender with a current documented company-domain relationship, an
unavailable check alone cannot veto an explicitly benign AI assessment with a
factual explanation, clean technical findings and an ordinary link/document
action. Unknown senders retain the existing review path. Positive identity contradictions, authentication failures,
sensitive collection channels and incomplete file inspection retain precedence.
The UI respects such benign backend decisions when external reputation is
unavailable; it does not clear malicious detections or structural concerns.

## Reference acquisition

Identity extraction can read the bounded immediate signature after a selected
message's sign-off, without feeding that signature into action extraction or
crossing into quoted history. An explicitly signed legal organisation name can
recover an omitted claim. A claim is not proof of identity.

The maintained catalog includes a sourced Cefla company-domain reference checked
on 19 October 2026, expiring after 60 days. It records `cefla.it` for sender/reply
and `cefla.com` for website visits, based on the company's published
[terms](https://www.cefla.com/it/termini-e-condizioni/) and
[privacy contacts](https://www.cefla.com/it/privacy/). It grants no credentials,
payments or account-change permissions. Record-level validity is capped by the
catalog's overall validity; changing one record does not refresh all references.

For other companies, public lookup may inspect a bounded number of contact,
privacy, terms and legal pages on the independently resolved HTTPS site.
HTTP/DNS failures remain diagnostic data, never a company-domain relationship.
They are cached briefly and exported with the evidence. Redirects, similar
domain labels and common hosting providers do not establish ownership.

## DNS transport

Unreachable native DNS resolvers can fall back to a fixed HTTPS DNS endpoint
(`https://dns.google/resolve`) inside the same lookup deadline. Only the queried
DNS name and record type are sent, not message content. Responses are bounded;
unrelated answer names, truncated replies and DNS errors are not accepted.
Conclusive NXDOMAIN results do not trigger fallback. Names without a recognized
public suffix, Local only, and the environment setting
`FISHSTOP_DNS_HTTPS_FALLBACK=0` disable fallback. Current DNS observations do not
reconstruct historical SMTP authentication.

## Action provenance

Remote inline images repeated in the plain-text MIME alternative remain
presentation resources, even when the text contains their URLs. Real image
buttons retain their destination as actionable. A cited email address by itself
is not a security CTA. Instructions inside a PDF cannot turn an unrelated body
link into the email's requested destination. Identity scoring uses the extracted
action channel rather than treating every embedded document URI as a sensitive
action destination. File inspection and grounded phishing assessments still
evaluate the document itself.
