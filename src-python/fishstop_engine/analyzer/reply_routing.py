"""Reply routing policy. Header claims alone never authenticate a service."""
from urllib.parse import urlsplit

from fishstop_engine.domain_utils import mailbox_candidates, registered_domain

HIGH_MESSAGE = "The reply address differs from the sender and no supported sharing or notification routing was established. Replies may reach a different recipient."
LOOKALIKE_MESSAGE = "The reply address uses a domain that imitates the sender, the recipient organisation or a known brand. Replies would reach a different, deceptive recipient."
FREEMAIL_MESSAGE = "The reply address is a personal mailbox provider account while the sender claims an organisation domain that could not be independently authenticated. Replies would bypass the sender's organisation."
FREEMAIL_AUTHENTICATED_MESSAGE = "The reply address is a personal mailbox provider account although the organisation sender was authenticated. Verify the reply destination before sending sensitive information."
CROSS_DOMAIN_MESSAGE = "The reply address belongs to a different domain than the sender. This is common for helpdesk or CRM services, but replies reach a different organisation: verify before sending sensitive information."
BULK_MESSAGE = "The authenticated bulk sender routes replies to a different domain, a common helpdesk or CRM configuration. Replies reach a different organisation."
SAME_ORGANISATION_MESSAGE = "The reply address is a different mailbox of the sender's organisation."
REVIEW_MESSAGE = "Sharing or notification routing was recognized, but the service sender could not be independently authenticated. Verify the reply destination."
SERVICE_MESSAGE = "The reply address differs from the sender as part of authenticated sharing or notification routing. This does not authenticate the reply recipient or the message content."

# Documented system mailboxes, not display names or broad domain allowlists.
# https://workspaceupdates.googleblog.com/2020/10/dynamic-emails-google-drive-access-requests-gmail.html
# https://support.microsoft.com/en-us/sharepoint/documents-and-library/manage-view-or-delete-sharepoint-alerts
SERVICE_DESTINATIONS = {
    "drive-shares-dm-noreply@google.com": ("drive.google.com", "docs.google.com"),
    "no-reply@sharepointonline.com": ("sharepoint.com",),
}


def assess_reply_routing(report: dict) -> dict:
    if report.get("selected_target_authentication_scope") == "embedded_unavailable":
        return {"level": "NONE", "message": "", "exception": False}
    senders = [address.casefold() for _, address in mailbox_candidates(report.get("from_") or "")]
    replies = [address.casefold() for _, address in mailbox_candidates(report.get("reply_to") or "")]
    if not replies or (len(senders) == 1 and all(reply == senders[0] for reply in replies)):
        return {"level": "NONE", "message": "", "exception": False}
    result = {"level": "HIGH", "message": HIGH_MESSAGE, "exception": False}
    if len(senders) != 1 or len(replies) != 1:
        return result
    sender = senders[0]
    sender_domain = sender.rsplit("@", 1)[-1]
    proof = report.get("domain_authentication") or {}
    authenticated = proof.get("status") == "verified" and any(
        registered_domain(domain) == registered_domain(sender_domain)
        for domain in proof.get("verified_domains") or []
    )
    allowed = SERVICE_DESTINATIONS.get(sender, ())
    destinations = []
    for link in report.get("links") or []:
        if link.get("actionable") is False:
            continue
        try:
            url = urlsplit(str(link.get("url") or ""))
            if url.scheme in {"http", "https"}:
                destinations.append(url)
        except ValueError:
            return result
    known_service = bool(allowed and destinations) and all(
        url.scheme == "https" and not url.username and not url.password
        and any(url.hostname == host or (host == "sharepoint.com" and (url.hostname or "").endswith(".sharepoint.com"))
                for host in allowed)
        for url in destinations
    )
    # Generic company notifications need independent authentication AND an
    # internal reply destination. Bulk/no-reply claims alone cannot bypass HIGH.
    internal_notification = bool(
        authenticated and report.get("is_bulk_sender")
        and registered_domain(sender_domain) == registered_domain(replies[0].rsplit("@", 1)[-1])
    )
    if internal_notification or (known_service and authenticated):
        return {"level": "INFO", "message": SERVICE_MESSAGE, "exception": True}
    if known_service and proof.get("status") not in {"failed", "invalid"}:
        return {"level": "MEDIUM", "message": REVIEW_MESSAGE, "exception": True}
    return _classify_unrecognized_routing(report, sender_domain, replies[0].rsplit("@", 1)[-1], authenticated)


def _classify_unrecognized_routing(report: dict, sender_domain: str, reply_domain: str, authenticated: bool) -> dict:
    """Grade a reply destination that no service exception explains.

    A different reply domain alone is a routing anomaly, not a phishing
    conviction: helpdesk and CRM platforms routinely use one. HIGH is kept for
    corroborated patterns: a deceptive lookalike reply domain, or a personal
    mailbox behind an unauthenticated organisation sender. The semantic policy
    separately escalates a sensitive request that asks for a reply.
    """
    from fishstop_engine.analyzer.lookalike import (
        _public_email_provider, check_lookalike_domains, protected_brands,
    )
    sender_registered = registered_domain(sender_domain)
    reply_registered = registered_domain(reply_domain)
    if not sender_registered or not reply_registered:
        return {"level": "HIGH", "message": HIGH_MESSAGE, "exception": False}
    if sender_registered == reply_registered:
        return {"level": "LOW", "message": SAME_ORGANISATION_MESSAGE, "exception": False}
    if (report.get("domain_authentication") or {}).get("status") in {"failed", "invalid"}:
        # The sender failed an explicit independent verification: a reply to
        # another organisation is then a corroborated hijack pattern.
        return {"level": "HIGH", "message": HIGH_MESSAGE, "exception": False}
    sender_is_mailbox_provider = _public_email_provider(sender_registered)
    reply_is_mailbox_provider = _public_email_provider(reply_registered)
    if not reply_is_mailbox_provider:
        brands = [sender_registered] + [brand for brand in protected_brands(report) if brand != sender_registered]
        alerts = check_lookalike_domains([{"host": reply_domain, "url": "mailto:reply@" + reply_domain}], known_brands=brands)
        if any(str(alert.get("level") or "").upper() == "HIGH" for alert in alerts):
            return {"level": "HIGH", "message": LOOKALIKE_MESSAGE, "exception": False}
    if reply_is_mailbox_provider and not sender_is_mailbox_provider:
        if authenticated:
            return {"level": "MEDIUM", "message": FREEMAIL_AUTHENTICATED_MESSAGE, "exception": False}
        return {"level": "HIGH", "message": FREEMAIL_MESSAGE, "exception": False}
    if authenticated and report.get("is_bulk_sender") and not reply_is_mailbox_provider:
        return {"level": "LOW", "message": BULK_MESSAGE, "exception": False}
    return {"level": "MEDIUM", "message": CROSS_DOMAIN_MESSAGE, "exception": False}


def refresh_reply_routing(report: dict) -> dict:
    assessment = assess_reply_routing(report)
    report["reply_to_routing"] = assessment
    report["flags"] = [flag for flag in report.get("flags") or []
                       if str(flag.get("field") or "").casefold() != "reply-to"]
    if assessment["level"] != "NONE":
        report["flags"].append({"field": "Reply-To", "level": assessment["level"], "message": assessment["message"]})
    return assessment
