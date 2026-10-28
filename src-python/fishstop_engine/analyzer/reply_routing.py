"""Reply routing policy. Header claims alone never authenticate a service."""
from urllib.parse import urlsplit

from fishstop_engine.domain_utils import mailbox_candidates, registered_domain

HIGH_MESSAGE = "The reply address differs from the sender and no supported sharing or notification routing was established. Replies may reach a different recipient."
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
    return result


def refresh_reply_routing(report: dict) -> dict:
    assessment = assess_reply_routing(report)
    report["reply_to_routing"] = assessment
    report["flags"] = [flag for flag in report.get("flags") or []
                       if str(flag.get("field") or "").casefold() != "reply-to"]
    if assessment["level"] != "NONE":
        report["flags"].append({"field": "Reply-To", "level": assessment["level"], "message": assessment["message"]})
    return assessment
