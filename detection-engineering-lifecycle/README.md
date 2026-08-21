# Detection Engineering Lifecycle

How a detection goes from idea to production to retirement: authoring, testing,
tuning, measuring, and deprecating.

The main deliverable is `docs/LIFECYCLE.md`. It builds a lifecycle model on
SigmaHQ's real five-value `status` enum (`experimental`, `test`, `stable`,
`deprecated`, `unsupported`), maps Palantir's ADS documentation framework onto
the promotion gates between those stages, and adds two states the Sigma spec
does not have: `muted` (in production, currently silenced, with a reason) and
`retired` (the underlying threat is gone, as distinct from being replaced by
another rule). The worked example walks the real `leak-extraction` rule from
the sibling `llm-abuse-detection` project through every stage and finds it
fires zero times across a 2,810-prompt corpus, invisible inside a headline
83.5% F1 score. Full sourcing, with PRIMARY / SECONDARY / GAP markings, is in
`docs/SOURCES.md`.

## The headline point

A headline metric can hide a dead rule. `leak-extraction` never fires once,
and the detector still scores 99.7% precision, because the other six rules
carry it. The only way to see this is to ask each rule for its own numbers,
which most detection programs never do until something forces them to.

## The linter

`src/lint_detection.py` reads a Sigma-shaped rule file (or a directory of
them) and checks it against this document's own requirements: `status` is one
of the five valid Sigma values, the mandatory fields are present and
non-empty, a `stable` rule has documented validation steps and a real
false-positive list, and a `deprecated` rule names either its replacement or
its retirement reason.

It is not a Sigma parser. It reads a small flat `key: value` and
block-list subset, described in the script's own docstring, and is explicit
that a file passing this linter is Sigma-**shaped**, not Sigma-**valid**.

Run it against the example rules:

```
python3 src/lint_detection.py examples/
```

Expected output: three rules pass, one (`BAD_stable_missing_validation.yml`)
fails with two specific, named problems.

## Tests

```
python3 -m pytest tests/ -q
```

## Layout

```
docs/LIFECYCLE.md   the main deliverable
docs/SOURCES.md      every framework cited, PRIMARY/SECONDARY/GAP marked
src/lint_detection.py   the linter
examples/*.yml       three passing example rules, one that fails on purpose
tests/test_lint.py   tests for the linter
```
