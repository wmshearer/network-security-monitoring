import json


def dispatch_loop_appends_raw_result(call, impl, messages):
    result = impl(**{})
    messages.append(
        {
            "role": "tool",
            "tool_call_id": call["id"],
            # ruleid: tool-result-into-conversation-untiered
            "content": json.dumps(result),
        }
    )


def dispatch_loop_appends_sanitized_result(call, impl, messages):
    result = impl(**{})
    safe_result = json.dumps(sanitize_tool_result(result))
    # ok: tool-result-into-conversation-untiered
    messages.append(
        {
            "role": "tool",
            "tool_call_id": call["id"],
            "content": safe_result,
        }
    )


def dispatch_loop_appends_static_ack(call, messages):
    # ok: tool-result-into-conversation-untiered
    messages.append(
        {
            "role": "tool",
            "tool_call_id": call["id"],
            "content": "ok",
        }
    )
