def retrieve(query):
    return [Doc(text="some corpus text")]


def build_messages_vulnerable(user_message):
    retrieved = retrieve(user_message)
    context_block = "\n\n---\n\n".join(d.text for d in retrieved)

    # ruleid: untrusted-retrieval-into-prompt
    user_content = f"Relevant internal documents:\n{context_block}\n\nQuestion: {user_message}"

    return [
        {"role": "system", "content": "You are a helpful assistant."},
        # ruleid: untrusted-retrieval-into-prompt
        {"role": "user", "content": user_content},
    ]


def build_messages_vulnerable_direct_doc_text():
    doc = retrieve("q")[0]
    # ruleid: untrusted-retrieval-into-prompt
    prompt = f"Reference: {doc.text}"
    return prompt


def build_messages_safe_sanitized(user_message):
    retrieved = retrieve(user_message)
    context_block = "\n\n---\n\n".join(d.text for d in retrieved)
    safe_block = sanitize_retrieved_text(context_block)

    # ok: untrusted-retrieval-into-prompt
    user_content = f"Relevant internal documents:\n{safe_block}\n\nQuestion: {user_message}"

    return [
        {"role": "system", "content": "You are a helpful assistant."},
        # ok: untrusted-retrieval-into-prompt
        {"role": "user", "content": user_content},
    ]


def build_messages_safe_no_retrieval(user_message):
    # ok: untrusted-retrieval-into-prompt
    user_content = f"Question: {user_message}"
    return [
        {"role": "system", "content": "You are a helpful assistant."},
        # ok: untrusted-retrieval-into-prompt
        {"role": "user", "content": user_content},
    ]


def build_messages_safe_static_system_prompt():
    # ok: untrusted-retrieval-into-prompt
    return [
        {"role": "system", "content": "You are a helpful assistant. Be concise."},
    ]
