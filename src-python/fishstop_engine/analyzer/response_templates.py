"""Canonical display copy built from grounded, policy-normalized AI values."""

CONTENT_SUMMARY_SOURCE = "template-v1"

_ACTIONS = {
    "provide_credentials": "The email asks the recipient to provide login credentials or authentication secrets.",
    "provide_information": "The email asks the recipient to provide personal or confidential information.",
    "pay_or_transfer": "The email asks the recipient to make a payment or transfer money.",
    "change_account_settings": "The email asks the recipient to change account settings.",
    "verify_account": "The email asks the recipient to verify account activity.",
    "claim_reward": "The email asks the recipient to claim a reward or benefit.",
    "bypass_procedure": "The email asks the recipient to bypass a normal procedure.",
    "visit_link": "The email asks the recipient to follow a link.",
    "open_attachment": "The email asks the recipient to open or review an attachment.",
    "reply": "The email asks the recipient to reply.",
    "informational": "The email provides information without a clearly identified recipient action.",
    "none": "No recipient action was identified in the email.",
    "other": "The requested action could not be classified precisely.",
}

_CHANNELS = {
    "supplied_link": "The request uses a link supplied in the email.",
    "supplied_attachment": "The request uses an attachment supplied with the email.",
    "external_form": "The request uses a form referenced in the email.",
    "email_reply": "The request uses an email reply.",
    "phone": "The request uses a phone interaction.",
    "normal_known_procedure": "The request refers to an independently known procedure.",
}


def content_summary_parts(semantic: dict) -> list[str]:
    """Use final corrected fields; never interpolate attacker-controlled prose."""
    action = semantic.get("requested_action")
    channel = semantic.get("action_channel")
    if semantic.get("structured_extortion"):
        opening = "The email demands payment and uses a threat to obtain compliance."
    else:
        opening = _ACTIONS.get(action, _ACTIONS["other"])
    parts = [opening]
    # Informational messages cannot inherit a spurious channel. Avoid repeating
    # the same link/attachment/reply description for a generic action.
    redundant = {("visit_link", "supplied_link"),
                 ("open_attachment", "supplied_attachment"), ("reply", "email_reply")}
    if action not in {"none", "informational"} and (action, channel) not in redundant:
        if channel in _CHANNELS:
            parts.append(_CHANNELS[channel])
    return parts
