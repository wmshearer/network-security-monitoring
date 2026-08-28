"""Pin the raw facts about the corpus that every other claim in this
project depends on. If these fail, nothing downstream can be trusted.
"""
from __future__ import annotations

import re

from conftest import T1558, requires_corpus

EVENT_RE = re.compile(r"Name='(\w+)'>([^<]*)<")


def _parse_events(path):
    events = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        fields = dict(EVENT_RE.findall(line))
        events.append(fields)
    return events


@requires_corpus
def test_single_event_log_has_exactly_one_event():
    path = T1558 / "kerberoasting_spn_request_with_rc4_encryption" / "windows-xml.log"
    events = _parse_events(path)
    assert len(events) == 1
    assert events[0]["TicketEncryptionType"] == "0x17"
    assert events[0]["TicketOptions"] == "0x40810000"


@requires_corpus
def test_volumetric_log_has_159_events():
    path = T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    events = _parse_events(path)
    assert len(events) == 159


@requires_corpus
def test_volumetric_log_ticket_options_does_not_match_reference_detection_filter():
    """The reference Splunk/Sigma detection filters TicketOptions to one of
    0x40810000 / 0x40800000 / 0x40810010. This dataset's TicketOptions is
    ALWAYS 0x60810010, a fourth value the reference filter does not list.
    This is why the base rule fires zero times on this dataset (see
    evidence/11_zircolite_base_only_on_jsonl.txt) and why the volumetric
    case cannot be answered as "the base rule just needs a threshold added
    on top" without first noticing the field values themselves differ.
    """
    path = T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    events = _parse_events(path)
    ticket_options = {e["TicketOptions"] for e in events}
    assert ticket_options == {"0x60810010"}
    reference_filter_values = {"0x40810000", "0x40800000", "0x40810010"}
    assert ticket_options.isdisjoint(reference_filter_values)


@requires_corpus
def test_volumetric_log_two_principals_counts():
    path = T1558 / "unusual_number_of_kerberos_service_tickets_requested" / "windows-xml.log"
    events = _parse_events(path)
    from collections import Counter

    counts = Counter(e["TargetUserName"] for e in events)
    assert counts == {
        "AR-WIN-2$@ATTACKRANGE.LOCAL": 111,
        "AR-WIN-DC$@ATTACKRANGE.LOCAL": 48,
    }
