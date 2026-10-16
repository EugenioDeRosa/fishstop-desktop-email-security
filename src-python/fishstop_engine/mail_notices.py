"""Narrow recognition of mail-client informational notices, never a host allowlist."""
import re
from urllib.parse import urlsplit


def is_sender_identification_notice_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        return (parsed.scheme == "https" and parsed.netloc.lower() == "aka.ms"
                and parsed.path == "/LearnAboutSenderIdentification"
                and not parsed.query and not parsed.fragment)
    except ValueError:
        return False


_NOTICE = re.compile(
    r"(?:Non ricevi spesso messaggi di posta elettronica da [^\n<>]{1,200}?\.\s*"
    r"Scopri perché è importante|You don't often get email from [^\n<>]{1,200}?\.\s*"
    r"Learn why this is important)\s*<?https://aka\.ms/LearnAboutSenderIdentification>?(?![\w/?#])",
    re.IGNORECASE,
)


def remove_sender_identification_notice(text: str) -> str:
    return _NOTICE.sub(" ", text)
