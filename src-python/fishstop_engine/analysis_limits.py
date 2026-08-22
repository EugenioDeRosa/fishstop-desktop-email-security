"""Central safety limits for analysis of untrusted email files."""

MAX_EML_BYTES = 10 * 1024 * 1024
MAX_MIME_PARTS = 200
MAX_MIME_DEPTH = 10
MAX_DECODED_TEXT_CHARS = 240_000
MAX_AI_BODY_CHARS = 120_000
MAX_ATTACHMENTS = 25
MAX_LINKS = 100
MAX_RECEIVED_HOPS = 50
MAX_PHI4_SECTIONS = 12


class EmailAnalysisLimitError(ValueError):
    """Raised when an email exceeds a supported analysis safety limit."""

