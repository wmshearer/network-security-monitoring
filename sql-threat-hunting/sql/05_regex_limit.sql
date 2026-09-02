-- Where SQL stops being the right tool.
--
-- SQLite does not ship a REGEXP implementation. From sqlite.org:
--
--   "No regexp() user function is defined by default and so use of the REGEXP
--    operator will normally result in an error message. If an
--    application-defined SQL function named 'regexp' is added at run-time,
--    then the 'X REGEXP Y' operator will be implemented as a call to
--    regexp(Y,X)."
--
-- I wrote this file expecting it to fail in the sqlite3 shell. It did not,
-- and the reason is worth more than the point I was originally making.
--
-- On this machine, both the CLI and Python report SQLite 3.46.1. Same
-- version. But:
--
--   $ sqlite3 :memory: "SELECT 'abc' REGEXP 'b';"     ->  1
--   >>> sqlite3.connect(':memory:').execute("SELECT 'abc' REGEXP 'b'")
--       OperationalError: no such function: REGEXP
--
-- The shell binary ships with a regexp function registered. The library that
-- Python links against does not. So availability is a property of the HOST
-- APPLICATION, not of SQLite the version, and testing in the shell tells you
-- nothing about whether your code will work.
--
-- That is the sharper lesson, and it is the kind of thing that only turns up
-- by running the query in both places rather than trusting either one.
--
-- It also matters practically. pySigma's SQLite backend maps Sigma's `re`
-- modifier straight onto REGEXP. A rule using a regex will work when tested
-- in the shell and then fail inside a Python detection pipeline, which is the
-- worst order to discover it in.
--
-- Try both:
--   sqlite3 data/events.db < sql/05_regex_limit.sql     (works here)
--   python3 src/regexp_demo.py                          (fails, then works)

SELECT
    capture,
    source_ip,
    destination_ip,
    protocol,
    COUNT(*) AS packets
FROM events
WHERE protocol REGEXP '^(LDAP|KRB5|SMB2?)$'
GROUP BY capture, source_ip, destination_ip, protocol
ORDER BY packets DESC;
