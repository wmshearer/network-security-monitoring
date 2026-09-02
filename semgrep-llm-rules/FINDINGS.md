# Findings

## Semgrep version tested

`semgrep --version` reported **1.174.0** (OSS, LGPL-2.1 engine, no Pro license, no
`--pro` flag used anywhere in this project). Installed into a local venv at `.venv/`.

## The OSS/Pro boundary experiment

Semgrep's own docs say, verbatim: "Interprocedural taint analysis is a Semgrep Pro
feature." Rather than take that on faith, we built a minimal, controlled test to
measure it directly.

**Setup** (`tests/oss_boundary/`): one taint rule file, `boundary_rule.yml`, with two
taint-mode rules that are otherwise identical (`source()` as the pattern-source,
`sink(...)` as the pattern-sink). Two target files:

- `intraprocedural.py`: `source()` and `sink()` are called in the same function.
- `interprocedural.py`: `source()` is called in `function_a`, its result is passed
  as an argument into `function_b`, and only `function_b` calls `sink()`.

**Run** (plain `semgrep`, no Pro flags, both target files scanned separately against
the same rule file):

```
--- intraprocedural.py ---
findings: 2   (both rules fire, line 12: sink(val))

--- interprocedural.py ---
findings: 0   (neither rule fires)
```

Full captured output: `logs/oss_boundary_run.log`.

**Result**: the intraprocedural flow produced 2 findings (both rules fired, correctly).
The interprocedural flow, with the exact same source/sink shape and only the call
graph changed, produced 0 findings. Both rules stayed completely silent. This
empirically confirms the documented claim: **OSS Semgrep taint mode does not track
dataflow across a function call boundary.** It is not a soft limitation or a
"sometimes" thing in this test; it's a hard wall the tool did not attempt to cross.

A second, related limitation surfaced organically while building rule (b) below, not
from a synthetic test: **Semgrep taint-mode `pattern-sanitizers` only clear a
tainted variable when the sanitizer pattern actually reassigns that variable to a
"clean" value** (the canonical idiom is `x = sanitize(x)`). A bare call to an
authorization function that merely gates a branch with `if/else` or `if/return`,
without reassigning the tainted variable, does **not** register as a sanitizer, even
though it is a completely correct authorization check in real code. We hit this
directly: the real target's dispatch loop calls `authorize()` and then only executes
`impl(**fn_args)` inside the `if decision.allowed:` branch, but never reassigns
`fn_args`. A naive `pattern-sanitizers: [pattern: authorize(...)]` entry did nothing;
both the authorized and unauthorized call sites still lit up. We worked around this
with a `pattern-not-inside` structural exclusion instead of a taint sanitizer (see
rules b and e below), which is honestly a hack for one specific code shape, not a
general solution, and is documented as such directly in each rule's metadata `note`
field and inline YAML comments.

## Rules

| rule id | fires on target | true positives | false positives |
|---|---|---|---|
| `untrusted-retrieval-into-prompt` | yes | 2 (main.py:79, main.py:85 -- same underlying flow, f-string interpolation and the dict `content` it flows into) | 0 |
| `tool-dispatch-without-authz` | yes | 1 (main.py:182, the unauthorized `else` branch) | 0 (main.py:179, the authorized branch, correctly excluded) |
| `tool-result-into-conversation-untiered` | yes | 1 (main.py:189, `json.dumps(result)`) | 0 |
| `secret-in-system-prompt-reaches-reply` | **no, by design** | 0 (cross-file: config.py's `CANARY_SECRET` to main.py's `reply` return is invisible to OSS) | 0 |
| `unchecked-path-to-file-read` | yes | 1 (tools.py:68, `FAKE_FILESYSTEM.get(path)` in `read_file`) | 0 (tools.py:21, `lookup_employee`'s `.get(key)`, correctly excluded by requiring a path-like parameter name) |

Full run against the real target, saved as `logs/target_run.log` and
`logs/target_run.json`:

```
Scanning 21 files with 5 Code rules:
  Scanning 7 files with 5 python rules.
Findings: 5

main.py:79   untrusted-retrieval-into-prompt
main.py:85   untrusted-retrieval-into-prompt
main.py:182  tool-dispatch-without-authz
main.py:189  tool-result-into-conversation-untiered
tools.py:68  unchecked-path-to-file-read
```

Every one of these 5 findings lines up with a documented planted vulnerability in
the target's own VULN comments (rag.py, main.py:50-86, main.py:145-182, main.py:189,
tools.py:51-71). `secret-in-system-prompt-reaches-reply` produced 0 findings against
`config.py` + `main.py`, which is the expected, correct result for that rule: the
real flow (config.py:12 `CANARY_SECRET` into config.py:43-55 `SYSTEM_PROMPT`, then
into main.py:133 `reply = msg.get("content")`, then main.py:134 `return
ChatResponse(reply=reply, ...)`) crosses two files and several function calls, and
OSS taint analysis cannot see it. We confirmed the rule's *mechanics* are sound by
running it against a synthetic single-function version of the same flow: 1 finding,
as expected (the rule's own `ruleid:` test case demonstrates the same thing).

### Test suite

`semgrep --test tests/`: **5/5 rule/test pairs passed** (`logs/final_validate.log`).
Every rule has both `ruleid:` (must-fire) and `ok:` (must-not-fire) cases, including
adversarial "looks similar but isn't the pattern" cases:

- `untrusted-retrieval-into-prompt`: an `ok:` case with retrieved text piped through a
  `sanitize_retrieved_text()` call before interpolation, and an `ok:` case with no
  retrieval at all.
- `tool-dispatch-without-authz`: an `ok:` case where `authorize()` is called
  unconditionally before the dispatch (whole-function authorized), and a
  same-function `ruleid:`/`ok:` pair inside one branch-gated dispatch function (the
  real target's actual shape), plus a `ruleid:` case for a low-risk tool with no
  authz table entry at all (this rule cannot judge risk level, so it correctly still
  flags it -- a human has to decide that `lookup_employee` doesn't need gating).
- `tool-result-into-conversation-untiered`: an `ok:` case with
  `json.dumps(sanitize_tool_result(result))`, and an `ok:` case with a static string
  literal (no tool result at all).
- `secret-in-system-prompt-reaches-reply`: an `ok:` case where a secret exists in the
  function but never reaches the reply, and an `ok:` case with no secret at all.
- `unchecked-path-to-file-read`: an `ok:` case with `_normalize_posix_path()` called
  locally, an `ok:` case with `authorize()` gating the same-function read, and an
  `ok:` case for `lookup_employee` (a differently-named, non-path parameter).

## False positive check

Ran the rule pack (unchanged, no tuning needed) against three codebases with no LLM
prompt construction:

1. `ai-supply-chain-audit/src/audit.py` (1 file): **0 findings**
2. `mobile-static-analysis/src/analyse.py` + `tests/test_analysis.py` (2 files, the
   project's own vendored `venv/` was excluded): **0 findings**
3. `ai-redteam-harness/src/harness/*.py` + `scripts/*.py` + non-test files under
   `tests/*.py` (9 files) -- deliberately chosen because it's the *other* half of the
   same overall repo (the red-team runner/harness code, not the vulnerable target),
   so it is realistic, LLM-adjacent Python that a naive keyword-based rule would be
   likely to misfire on: **0 findings**

Total false positives across all three runs: **0**. No rule tuning was required.
Full output: `logs/false_positive_run.log`.

## Prior art, stated honestly

Semgrep already ships upwards of 100 public LLM-focused rules under
`ai/ai-best-practices/` (OpenAI, Anthropic, LangChain, MCP, Claude Code hooks), plus a
separate paid "Shadow AI" pack of 186 rules. We did not copy, vendor, or reference any
rule body from `semgrep/semgrep-rules` (custom "Semgrep Rules License v1.0", not OSS);
every rule here is original, written by reading the target code and Semgrep's public
taint-mode syntax documentation only.

The closest public rules and how ours differ:

- `openai-user-input-in-system-prompt-python`: taint rule, sources are Flask/Django
  request getters, sink is the literal `{"role": "system", "content": $SINK}` dict
  shape used by the OpenAI SDK. Ours (`untrusted-retrieval-into-prompt`) targets RAG
  content flowing into the **user** role, via a raw `httpx` call to an
  Ollama-compatible endpoint, not the OpenAI SDK. Different source, different role,
  different transport.
- `langchain-dangerous-exec`: LangChain-specific. The target has no LangChain
  dependency at all.
- `llm-output-to-exec-python`: sources are LLM API call returns, sinks are
  `eval`/`exec`/`os.system`. The target has no exec-style sink; the risk here is tool
  *dispatch* (`impl(**fn_args)`), not code execution.
- `mcp-unsanitized-return`: scoped to the `@server.tool()` MCP decorator. The target
  uses a plain dict dispatch table (`TOOL_IMPLS`), no MCP, no decorator.
- `hooks-unconditional-allow-generic`: regex-only, Claude Code/Cursor specific.

Honest positioning: the existing public rules are anchored to specific vendor SDK
function names and decorators. Ours are framework-agnostic (generic Python taint
shapes: dict literals, `**kwargs` dispatch, f-strings) and target two code patterns
(RAG-into-user-content via raw HTTP, and dict-based tool dispatch without an authz
gate) that the public rule set does not cover. This is an incremental extension of
the same idea to different code shapes, not a new category of detection.

Academically, **TaintP2X** (He et al., ICSE 2026, DOI 10.1145/3744916.3773199) is a
custom static taint framework purpose-built for "Prompt-to-Anything Injection" that
treats **LLM output** as the taint source (the model said something, and that
something reaches a dangerous sink downstream). Our rules point the other direction:
we treat retrieval/RAG content and tool-call arguments as the taint **source**, and
the LLM's prompt/message construction as the sink. Both are legitimate directions for
the same underlying problem (untrusted text mixing with instructions); we are not
claiming to replicate or supersede TaintP2X, just noting the two are complementary
and looking at opposite ends of the same pipe.

## What these rules cannot catch

Being specific about the limits, not just gesturing at them:

- **Taint analysis sees code shape, not runtime behavior.** None of these rules can
  tell you whether the model actually obeyed an injected instruction, whether a
  prompt injection attempt succeeded, or what the model's output actually said at
  runtime. A finding here means "untrusted data can structurally reach a sensitive
  location in the code," not "an attack happened" or "an attack would succeed." That
  gap is what the harness's actual red-team runs (garak, PyRIT) are for, not static
  analysis.
- **Cross-function and cross-file flows are invisible in OSS.** Confirmed
  empirically above. `secret-in-system-prompt-reaches-reply` is the clearest example:
  the real vulnerability spans two files and cannot be detected by this rule pack at
  all. Anyone relying on a clean run of that rule alone to mean "no system-prompt
  leakage risk" would be wrong, and the rule's own message says so.
- **Sanitizer recognition requires reassignment, not just a call.** A correct
  authorization check written as `if not authorize(...): deny() else: proceed()`
  does not register as sanitized unless the checked variable itself gets reassigned.
  We worked around this for two rules using `pattern-not-inside` structural
  exclusions, but that only recognizes the one code shape we tested against; a
  differently structured but equally correct authz check (a decorator, a context
  manager, a check inside a helper function one level removed) may not be recognized
  and could produce either a false positive (flagging code that is actually safe) or,
  worse, a false negative if the exclusion is too broad. This is a real fragility,
  not a solved problem.
- **No custom `pattern-propagators`.** OSS does not support the Pro-only
  `pattern-propagators` feature; we relied entirely on Semgrep's default propagation
  through assignment, string formatting, and standard call shapes. Any propagation
  path outside that default (e.g. through a custom serialization wrapper, a queue, a
  cache) will not be tracked.
- **No judgment about risk level or business context.** `tool-dispatch-without-authz`
  correctly flags `lookup_employee` calls even though that tool is deliberately
  low-risk and intentionally has no authz policy. The rule cannot know that; a human
  reviewer has to make that call. Similarly `tool-result-into-conversation-untiered`
  is marked LOW confidence because "tool result appended as a message" is also just
  the normal, correct shape of an agent loop -- this rule has no way to tell a
  sensitive tool result apart from a harmless one.
- **CWE-1426** ("Improper Validation of Generative AI Output") is cited in two rules
  where it fits the literature's usage (LLM-output-adjacent flows), but Semgrep's own
  CWE list support and mapping conventions for this relatively new CWE are still
  maturing; treat the citation as directionally correct, not as evidence of a formal,
  stable mapping.
