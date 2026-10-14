# QR invitations and selected payment messages

An explicit instruction to scan a code triggers local inspection of PDF and
image attachments. QR destinations enter the existing URL, lookalike and
configured reputation checks as `attachment_qr`; no QR destination is opened
by the decoder. Attachment text is supplied as untrusted evidence to the
existing AI pass. Decoding never executes attachment instructions.

Inspection uses one isolated child process per email, with a six-second budget,
at most six attachments, 12 MiB per attachment and 24 MiB total. PDF inspection
covers at most four pages per document with a rendered-image limit of eight
million pixels. Limits, crashes and unavailable decoders produce unavailable
or partial results, not proof of safety. Successfully decoded results survive
a later timeout. The decoder supports web URLs; non-web payloads are not actions.

A QR invitation requesting confirmation of information using a work email is
an information request. An unresolved requested QR destination requires review.
A different QR destination domain alone does not prove phishing. Existing
concrete evidence such as malicious URL reputation can still escalate.

Conversation selection preserves the target body separately from explicitly
selected context. Bank details plus an outstanding payment-proof condition are
recognised as an implicit transfer request in the target. The selected IBAN
message requires beneficiary confirmation, not an invented account change.
An IBAN alone or acknowledgement of an already received receipt does not
trigger this rule. A changed-payment finding still requires explicit evidence
in the selected scope. Authentication of the outer forwarding message never
authenticates embedded sender claims.

Regressions are anonymised and include legitimate counterexamples. Local audits
of the two user-supplied EMLs simulate an AI extraction that omits the action,
demonstrating that the deterministic correction recovers it independently.
