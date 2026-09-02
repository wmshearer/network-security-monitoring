"""Measure the identity-feature leak directly, instead of assuming it.

The claim behind this whole project's methodology is that benign and
malicious DoH traffic in this dataset come from different client machines,
so any feature that reveals identity (an IP address, a timestamp) lets a
model shortcut past the actual detection problem. That claim needs to be
checked against the real CSV, not taken on faith, and the two known public
DoH resolver IPs used by BOTH benign and malicious clients (Cloudflare,
Google, Quad9, AdGuard) mean a naive "are the IP sets disjoint" check gives
the wrong answer if it isn't careful about which side of each flow is the
client and which is the resolver.
"""

from __future__ import annotations

import pandas as pd

# Public DoH resolver IPs that legitimately appear on both the benign and
# malicious sides: every DoH client, tunneling or not, has to talk to some
# resolver, and this dataset's captures used a small, known set of them.
# These are excluded when computing CLIENT-side IP overlap, since a shared
# resolver address is not identity leakage the way a shared client address
# would be. Confirmed against the actual l2-total-add.csv (see
# tests/test_leak_audit.py): every IP in the dataset is either one of
# these or a private 192.168.0.0/16 client address, and this list is
# exactly the set of non-private (public) addresses observed.
KNOWN_DOH_RESOLVERS: frozenset[str] = frozenset(
    {
        "1.1.1.1",  # Cloudflare
        "8.8.8.8", "8.8.4.4",  # Google
        "9.9.9.9", "9.9.9.11",  # Quad9
        "176.103.130.130", "176.103.130.131",  # AdGuard
    }
)


def client_ips(frame: pd.DataFrame, resolvers: frozenset[str] = KNOWN_DOH_RESOLVERS) -> set[str]:
    """All SourceIP/DestinationIP values in `frame` that are not a known
    resolver, i.e. the addresses that identify a capture's client machine.
    """
    ips = set(frame["SourceIP"]) | set(frame["DestinationIP"])
    return ips - resolvers


def ip_overlap_report(frame: pd.DataFrame, group_col: str) -> dict:
    """For each value of `group_col` (e.g. Label, or tool), the set of
    client IPs seen, and the pairwise overlaps between groups.

    Returns a dict with `ips_by_group` (group -> sorted IP list) and
    `overlaps` (a list of (group_a, group_b, shared_ips) for every pair
    with a nonempty intersection). An empty `overlaps` list is the
    "disjoint" result the detection methodology depends on.
    """
    groups = sorted(frame[group_col].unique())
    ips_by_group = {g: client_ips(frame[frame[group_col] == g]) for g in groups}

    overlaps = []
    for i, a in enumerate(groups):
        for b in groups[i + 1 :]:
            shared = ips_by_group[a] & ips_by_group[b]
            if shared:
                overlaps.append((a, b, sorted(shared)))

    return {
        "ips_by_group": {g: sorted(ips) for g, ips in ips_by_group.items()},
        "overlaps": overlaps,
    }
