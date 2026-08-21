# Semgrep rules for LLM application vulnerabilities

This is a small set of Semgrep rules that look for specific, risky code patterns in
LLM-application code: places where untrusted text (retrieved documents, tool
results, model-supplied arguments) flows into a prompt or a dangerous action without
passing through a check first.

## What is static analysis

Static analysis means reading source code and reasoning about it without running the
program. No model is called, no server is started, nothing executes. A static
analyzer parses your code into a structure it can search, then looks for patterns:
"is this function called anywhere with an unescaped string," "does this variable ever
get passed to `eval()`." Semgrep is a static analysis tool built around
"pattern matching that looks like code," which is why its rules read almost like the
language they analyze.

The upside of static analysis is speed and coverage: it can check every line of a
codebase in seconds, before anything ships, without needing a running instance of
the app or test data. The downside is that it only knows what the code's shape tells
it. It cannot see what actually happens when the program runs, and it cannot know
your intent. That's the tradeoff behind everything in this project.

## What taint (dataflow) analysis adds

A plain pattern match asks "does this line look dangerous." Taint analysis asks a
better question: "does a value that came from somewhere untrusted ever reach
somewhere dangerous, and if so, by what path." It works by naming three things in a
rule:

- a **source**: where untrusted data enters the picture (a function that returns
  text from an external document, for example)
- a **sink**: where it would be dangerous for that data to end up (a place that gets
  treated as a trusted instruction, or executes something)
- a **sanitizer** (optional): a place along the way where the data gets cleaned or
  checked, after which it's no longer considered tainted

The analyzer then traces whether a value can travel from a source to a sink without
passing through a sanitizer. If it can, that's a finding. This is more useful than a
plain pattern match because the risky part usually isn't any single line, it's the
combination: untrusted input reaching a sensitive spot with nothing in between to
stop it. "Data flows from here to there without passing through a check" is exactly
the shape of most real injection and authorization bugs, so tracing that path is a
much better signal than just flagging every occurrence of a risky-looking function
by itself.

## Why this matters for LLM applications specifically

LLM apps have a structural weak point that traditional web apps mostly don't: the
model reads everything in its context (system prompt, user message, retrieved
documents, tool results) as one undifferentiated stream of text, and it has no
built-in way to tell "instructions I should follow" apart from "reference data I
should just read." If a retrieved document, a tool's output, or a user's message
contains something that looks like an instruction, the model can end up following
it. This is called prompt injection, and it's the top entry on OWASP's LLM Top 10
for a reason.

Taint analysis is a good fit for finding this class of bug in code, because the
question is exactly "does untrusted text reach the prompt/message construction
without being separated or marked as untrusted first." That's a dataflow question,
not a single-pattern question.

## What this project actually contains

- `rules/`: five original Semgrep taint-mode rules. Three work as intended against a
  real vulnerable target. Two are included specifically to demonstrate a real limit
  of the free version of Semgrep (cross-function and cross-file dataflow), and they
  say so plainly in their own output.
- `tests/`: a test file for every rule with both "this should be flagged" and "this
  should not be flagged" example code, run with `semgrep --test`.
- `tests/oss_boundary/`: a small, separate experiment that measures (rather than
  assumes) where Semgrep's free engine stops being able to trace dataflow.
- `logs/`: the actual captured output of every run referenced in `FINDINGS.md`.
- `FINDINGS.md`: version tested, the boundary experiment's real output, each rule's
  results against a real vulnerable target and against clean code, prior art, and an
  honest list of what these rules cannot catch.

## What this is not

This is not a claim that static analysis can tell you whether an LLM application is
actually safe to run. It cannot see whether a model obeys an injected instruction,
and it cannot evaluate anything about the model's actual behavior at runtime. It can
only tell you whether the code's structure has a gap where untrusted data could reach
somewhere sensitive without a check in between. That's a real and useful thing to
know before you ship, but it's a code-shape check, not a safety guarantee.
