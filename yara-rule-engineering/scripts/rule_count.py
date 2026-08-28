r"""
Count top-level "rule <name> { ... }" declarations in raw YARA source text,
independent of which engine compiles it. Used so script 02 (yara-python) and
script 03 (yara-x) can report a rule count per file even for files where one
engine fails to compile and the other succeeds (yara-x's Rules object has no
public API to enumerate rule names/count in yara-x 1.20.0, unlike
yara-python's `len(list(compiled_rules))`).

Method: a single-pass linear scanner (not a single monolithic regex) walks
the source character by character, tracking whether it is inside a block
comment, a line comment, a double-quoted string, or a `/regex/` pattern
literal, and emits everything else unchanged. `rule <identifier>` is then
regex-matched on that cleaned text.

Two real bugs were found and fixed while building this, both against actual
files in the cloned rulesets (not synthetic tests):

1. A first version used one big regex with alternation between comment and
   string patterns; it under-counted on
   .rulesets/yara-rules/maldocs/Maldoc_APT19_CVE-2017-0199.yar (found 2 rules
   instead of 3) because on backslash-heavy strings like
   `"windir + \"\\syswow64\\..."` a regex-based scan can lose track of
   whether it is inside or outside a string across the whole remaining file.

2. The character-by-character scanner still under-counted the SAME file (2
   instead of 3) because it had no concept of a YARA regex pattern literal
   like `$psregex1 = /\W\w+\s+\s\".+\"/`. The `\"` inside that `/.../` is a
   regex escape, not a string escape, but the scanner (not yet knowing about
   regex literals) read the `"` in `\"` as an ordinary bare quote and opened
   a brand-new, unterminated string there, silently swallowing every rule
   declaration for the rest of the file. Fixed by recognizing `/` as the
   start of a regex literal (not division or a `//` comment) whenever it is
   immediately preceded, ignoring whitespace, by `=`, `(`, `,` and NOT
   already inside a comment/string, matching where YARA's own grammar
   permits a regex pattern to start.

This is a structural count, not a compile result: a rule counted here can
still fail to compile.

Cross-checked in tests/test_rule_count.py against yara-python's authoritative
len(list(yara.compile(...))) on every file that DOES compile under
yara-python: the two must agree everywhere, or this counter is not trustworthy
and the discrepancy must be investigated, not silently accepted.
"""
import re

_RULE_DECL = re.compile(r"(?:^|\n)\s*(?:private\s+|global\s+)*rule\s+[A-Za-z_]\w*")


def strip_comments_and_strings(source: str) -> str:
    """Replace block comments, line comments, and double-quoted string
    literals with a single space each, via an explicit linear scan that
    tracks string/comment state exactly (see module docstring for why a
    monolithic regex was not good enough)."""
    out = []
    i = 0
    n = len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append(" ")
            i = j
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            out.append(" ")
            i = j
            continue
        if ch == '"':
            i += 1
            while i < n:
                if source[i] == "\\" and i + 1 < n:
                    i += 2
                    continue
                if source[i] == '"':
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue
        if ch == "/":
            # Look back (skipping whitespace already emitted) for a char
            # that legally precedes a YARA regex pattern literal.
            k = len(out) - 1
            while k >= 0 and out[k] in (" ", "\t"):
                k -= 1
            prev = out[k] if k >= 0 else ""
            if prev in ("=", "(", ","):
                j = i + 1
                closed = False
                while j < n:
                    if source[j] == "\\" and j + 1 < n:
                        j += 2
                        continue
                    if source[j] == "\n":
                        break  # not a valid regex literal, bail out
                    if source[j] == "/":
                        j += 1
                        closed = True
                        break
                    j += 1
                if closed:
                    # consume optional modifiers (e.g. "i", "s", "is")
                    while j < n and source[j] in ("i", "s"):
                        j += 1
                    out.append(" ")
                    i = j
                    continue
        out.append(ch)
        i += 1
    return "".join(out)


def count_rule_declarations(source: str) -> int:
    stripped = strip_comments_and_strings(source)
    return len(_RULE_DECL.findall(stripped))
