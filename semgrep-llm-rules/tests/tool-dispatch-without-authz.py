import json


def dispatch_no_authz_at_all(call, impl):
    # No authorization check exists anywhere in this function.
    fn_args = json.loads(call["function"]["arguments"])
    # ruleid: tool-dispatch-without-authz
    result = impl(**fn_args)
    return result


def dispatch_branch_gated_no_authz(call, impl, fn_name, authz_enabled):
    fn_args = json.loads(call["function"]["arguments"])
    if impl is None:
        result = {"error": "unknown tool"}
    elif authz_enabled and fn_name in ("send_email", "read_file"):
        decision = authorize(fn_name, fn_args)
        if not decision.allowed:
            result = {"error": "unauthorized"}
        else:
            # ok: tool-dispatch-without-authz
            result = impl(**fn_args)
    else:
        # ruleid: tool-dispatch-without-authz
        result = impl(**fn_args)
    return result


def dispatch_always_authorized(call, impl, fn_name):
    fn_args = json.loads(call["function"]["arguments"])
    decision = authorize(fn_name, fn_args)
    if not decision.allowed:
        result = {"error": "unauthorized", "reason": decision.reason}
    else:
        # ok: tool-dispatch-without-authz
        result = impl(**fn_args)
    return result


def dispatch_low_risk_tool_no_policy_needed(call, impl):
    # lookup_employee has no side effects and is deliberately excluded from
    # the authz table; calling it straight is the accepted, low-risk case.
    fn_args = json.loads(call["function"]["arguments"])
    # ruleid: tool-dispatch-without-authz
    result = impl(**fn_args)
    return result
