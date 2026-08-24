import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from poller import _parse_logevent_raw


def test_parses_logevent_raw_format():
    raw = (
        'detection=D1_registry_run_key_setvalue technique=T1547.001 '
        'search_name="D1 - Registry Run Key Persistence (T1547.001)" '
        'result_count=36 sid="scheduler__nobody_abc_at_123_4"'
    )
    fields = _parse_logevent_raw(raw)
    assert fields["detection"] == "D1_registry_run_key_setvalue"
    assert fields["technique"] == "T1547.001"
    assert fields["search_name"] == "D1 - Registry Run Key Persistence (T1547.001)"
    assert fields["result_count"] == "36"
    assert fields["sid"] == "scheduler__nobody_abc_at_123_4"


def test_parses_quoted_value_containing_spaces():
    # search_name values contain spaces and parens; this is the field most
    # likely to break a naive split(" ") parser, so it gets its own test.
    raw = 'detection=D5 technique=T1123 search_name="D5 - Process Access to Audio Device Graph Isolation (T1123)" result_count=74 sid="x"'
    fields = _parse_logevent_raw(raw)
    assert fields["search_name"] == "D5 - Process Access to Audio Device Graph Isolation (T1123)"


def test_dedupe_by_cd_excludes_previously_seen():
    from poller import new_alerts

    class FakeClient:
        def search(self, spl, earliest="0", latest="now", count=0):
            return {
                "results": [
                    {"_cd": "3:100", "_time": "t1", "_raw": 'detection=D1 technique=T1547.001 search_name="n" result_count=1 sid="s1"'},
                    {"_cd": "3:101", "_time": "t2", "_raw": 'detection=D2 technique=T1053.005 search_name="n" result_count=1 sid="s2"'},
                ]
            }

    seen = {"3:100"}
    fresh, all_cds = new_alerts(FakeClient(), seen, max_results=10)

    assert len(fresh) == 1
    assert fresh[0].detection == "D2"
    assert all_cds == {"3:100", "3:101"}
