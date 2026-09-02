#!/usr/bin/env python3
"""The exact check documented in the case study, section 05 ("Torii: the
same rule finds nothing"): which destination port Torii's real command-and-
control connections use. Split into its own file because the one-liner's
embedded quotes and newlines break termcap.sh's echoed-command heredoc.
"""
from collections import Counter
from src.labels import read_connections

conns = read_connections('data/CTU-IoT-Malware-Capture-20-1-Torii/bro/conn.log.labeled')
cc = [c for c in conns if c.detail == 'C&C' or c.detail.startswith('C&C')]
print(Counter(c.resp_port for c in cc))
