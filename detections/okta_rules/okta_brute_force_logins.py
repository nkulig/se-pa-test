from panther_base_helpers import deep_get, okta_alert_context


# RANDOM COMMENT
# RANDOM COMMENT TWO
# RADNOM COMMENT THREE
# RANDOM COMMENT FOUR

def rule(event):
    return (
        deep_get(event, "outcome", "result") == "FAILURE"
        and event.get("eventType") == "user.session.start"
    )


def title(event):
    return (
        f"Suspected brute force Okta logins to account "
        f"{deep_get(event, 'actor', 'alternateId', default='<UNKNOWN_ACCOUNT>')}, due to "
        f"[{deep_get(event, 'outcome', 'reason', default='<UNKNOWN_REASON>')}]"
    )


def alert_context(event):
    return okta_alert_context(event)
