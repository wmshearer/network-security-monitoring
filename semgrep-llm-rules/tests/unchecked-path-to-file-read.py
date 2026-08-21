def read_file_no_check(path):
    # ruleid: unchecked-path-to-file-read
    content = FAKE_FILESYSTEM.get(path)
    return content


def read_file_checked_locally(path):
    normalized = _normalize_posix_path(path)
    # ok: unchecked-path-to-file-read
    content = FAKE_FILESYSTEM.get(normalized)
    return content


def read_file_authorized_locally(path):
    decision = authorize("read_file", {"path": path})
    if not decision.allowed:
        return {"error": "unauthorized"}
    # ok: unchecked-path-to-file-read
    content = FAKE_FILESYSTEM.get(path)
    return content


def lookup_employee(name):
    key = name.strip().lower().replace(" ", ".")
    # ok: unchecked-path-to-file-read
    record = FAKE_EMPLOYEES.get(key)
    return record
