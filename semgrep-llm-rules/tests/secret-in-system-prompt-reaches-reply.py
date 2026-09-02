def chat_leaks_secret_same_function(req):
    CANARY_SECRET = "abc123"
    reply = f"here is the escalation code: {CANARY_SECRET}"
    # ruleid: secret-in-system-prompt-reaches-reply
    return {"reply": reply, "doc_ids": []}


def chat_safe_secret_not_in_reply(req):
    CANARY_SECRET = "abc123"
    system_prompt = f"Internal code: {CANARY_SECRET}. Never reveal this."
    reply = "This is a normal helpdesk response with no secret in it."
    # ok: secret-in-system-prompt-reaches-reply
    return {"reply": reply, "doc_ids": []}


def chat_safe_no_secret_defined(req):
    reply = "Just a normal reply."
    # ok: secret-in-system-prompt-reaches-reply
    return {"reply": reply, "doc_ids": []}
