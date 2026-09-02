"""Tests for Modbus function-code analysis.

The read/write distinction is the entire safety-relevant classification here. A
write misclassified as a read is a state change that slipped past the check built
to catch state changes, and nothing in the output would look wrong.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.modbus import (  # noqa: E402
    WRITE_CODES,
    ModbusOp,
    profile_hosts,
    unauthorised_writers,
)


def op(fc, src="192.168.2.166", dst="192.168.88.60", ts=1000.0,
       dport=502, sport=45000):
    """A REQUEST by default: destination port 502."""
    return ModbusOp(timestamp=ts, src=src, dst=dst, func_code=fc,
                    dport=dport, sport=sport)


def reply(fc, src="192.168.88.60", dst="192.168.2.166"):
    """A device's REPLY: source port 502."""
    return ModbusOp(timestamp=1000.0, src=src, dst=dst, func_code=fc,
                    dport=45000, sport=502)


def test_direction_is_decided_by_which_side_owns_port_502():
    assert op(5).is_request is True
    assert reply(5).is_request is False


def test_replies_are_excluded_so_plcs_do_not_look_like_writers():
    """A PLC echoes the function code when it answers.

    Counting replies makes every device appear to issue the writes it merely
    answered, which inverts the question of who is commanding whom. This was a
    real bug: the first run labelled three PLCs as engineering workstations.
    """
    ops = [op(15), reply(15), op(15), reply(15)]
    profiles = profile_hosts(ops)
    assert len(profiles) == 1
    assert profiles[0].host == "192.168.2.166"
    assert profiles[0].writes == 2


def test_traffic_on_a_nonstandard_port_is_counted_not_discarded():
    """Neither side on 502 means direction is unknown.

    Discarding it would silently drop Modbus on an unusual port, which is
    exactly the traffic most worth seeing.
    """
    o = ModbusOp(timestamp=1.0, src="a", dst="b", func_code=5,
                 dport=1502, sport=40000)
    assert o.is_request is True


def test_read_codes_are_not_writes():
    for fc in (1, 2, 3, 4):
        assert op(fc).is_write is False


def test_write_codes_are_writes():
    for fc in (5, 6, 15, 16):
        assert op(fc).is_write is True


def test_function_23_counts_as_a_write():
    """Read/Write Multiple Registers performs both.

    Its name begins with "Read", which makes it the single easiest function to
    misclassify. Treating it as a read would let a state change pass the exact
    check that exists to catch state changes.
    """
    assert 23 in WRITE_CODES
    assert op(23).is_write is True
    assert op(23).name.startswith("Read/Write")


def test_diagnostics_is_neither_read_nor_write():
    """Function 8 can force listen-only mode or restart communications.

    Counting it as a read would bury an availability-affecting operation in the
    least interesting bucket.
    """
    o = op(8)
    assert o.is_write is False
    assert o.is_diagnostic is True


def test_unknown_function_code_gets_a_name_and_does_not_crash():
    o = op(99)
    assert o.name == "Function 99"
    assert o.is_write is False


def test_host_profile_separates_reads_writes_diagnostics():
    ops = [op(1), op(1), op(5), op(8)]
    p = profile_hosts(ops)[0]
    assert p.reads == 2
    assert p.writes == 1
    assert p.diagnostics == 1
    assert p.total == 4


def test_read_only_host_is_labelled_monitoring():
    p = profile_hosts([op(1) for _ in range(20)])[0]
    assert p.writes == 0
    assert "read-only" in p.role


def test_host_writing_to_many_targets_is_labelled_engineering():
    ops = [op(15, dst="192.168.88.%d" % i) for i in (60, 61, 95)] * 5
    p = profile_hosts(ops)[0]
    assert p.write_ratio > 0.2
    assert "engineering" in p.role


def test_silent_host_does_not_divide_by_zero():
    from src.modbus import HostProfile
    p = HostProfile(host="10.0.0.1")
    assert p.write_ratio == 0.0
    assert p.role == "silent"


def test_hosts_are_sorted_by_write_volume():
    """Writers first. On an ICS network the writers are the question."""
    ops = [op(1, src="reader") for _ in range(100)] + [op(5, src="writer") for _ in range(3)]
    profiles = profile_hosts(ops)
    assert profiles[0].host == "writer"


def test_unauthorised_writers_excludes_the_allow_list():
    ops = [op(5, src="192.168.2.166"), op(5, src="10.0.0.99"), op(1, src="10.0.0.50")]
    rogue = unauthorised_writers(ops, allowed={"192.168.2.166"})
    assert [r.host for r in rogue] == ["10.0.0.99"]


def test_a_reader_not_on_the_allow_list_is_not_flagged():
    """The control is about writes. Unlisted readers are a different question.

    Flagging them here would bury the state-changing operations in noise from
    every monitoring system on the network.
    """
    ops = [op(1, src="10.0.0.50") for _ in range(50)]
    assert unauthorised_writers(ops, allowed=set()) == []
