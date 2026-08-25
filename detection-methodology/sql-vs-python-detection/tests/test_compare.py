"""Tests pinning the comparison findings, including the dead rule."""
import sqlite3, sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
DB = ROOT / "data" / "prompts.db"


@pytest.fixture(scope="module")
def conn():
    c = sqlite3.connect(DB)
    yield c
    c.close()


def test_corpus_is_balanced(conn):
    rows = dict(conn.execute("SELECT label, COUNT(*) FROM prompts GROUP BY label"))
    assert rows["malicious"] == 1405
    assert rows["benign"] == 1405


def test_both_engines_agree_on_every_prompt():
    """The precondition for the whole comparison. If the engines disagree the
    numbers are measuring two different rule sets, not two engines."""
    import compare
    conn = sqlite3.connect(DB)
    rules_mod = compare.load_python_rules()
    py, _ = compare.python_pass(conn, rules_mod)
    sq, _ = compare.sql_pass(conn, rules_mod)
    conn.close()
    disagreements = [k for k in py if py[k][0] != sq[k][0]]
    assert disagreements == []


def test_reproduces_the_original_projects_metrics():
    """The port must not have changed the rules. These are the numbers the
    llm-abuse-detection project published."""
    import compare
    conn = sqlite3.connect(DB)
    rules_mod = compare.load_python_rules()
    py, _ = compare.python_pass(conn, rules_mod)
    conn.close()
    m = compare.metrics(py)
    assert round(m["precision"], 3) == 0.997
    assert round(m["recall"], 3) == 0.718
    assert m["tp"] == 1009 and m["fp"] == 3 and m["fn"] == 396


def test_leak_extraction_rule_is_dead():
    """Finding 1. The rule never fires on this corpus, and that is invisible
    in the aggregate score."""
    import compare
    rules_mod = compare.load_python_rules()
    leak = [r for r in rules_mod.RULES if r.name == "leak-extraction"][0]
    conn = sqlite3.connect(DB)
    texts = [t for (t,) in conn.execute("SELECT text FROM prompts")]
    conn.close()
    fires = sum(1 for t in texts if leak.pattern.search(t))
    assert fires == 0, (
        f"leak-extraction now fires {fires} times. If a rule or the corpus "
        "changed, docs/FINDING.md needs rewriting."
    )


def test_the_concepts_it_should_catch_are_present(conn):
    """The rule is dead because of phrasing, not because the corpus lacks
    prompt-leak attempts."""
    n = conn.execute(
        "SELECT COUNT(*) FROM prompts WHERE lower(text) LIKE '%system prompt%'"
    ).fetchone()[0]
    assert n >= 9


def test_multi_rule_hits_are_always_malicious():
    """Finding 2. Two or more rules firing has been a perfect signal here."""
    import compare
    conn = sqlite3.connect(DB)
    rules_mod = compare.load_python_rules()
    py, _ = compare.python_pass(conn, rules_mod)
    conn.close()
    multi = [(f, h, l) for f, h, l in py.values() if len(h) >= 2]
    assert len(multi) > 500
    assert all(l == "malicious" for _f, _h, l in multi)
