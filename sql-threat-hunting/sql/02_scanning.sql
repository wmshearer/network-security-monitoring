-- Scanning: one source reaching for many destinations that never answer.
--
-- The give-away is not volume. A busy server also sends a lot of packets. The
-- give-away is the ratio of destinations touched to destinations that replied.
-- A scanner sprays and mostly gets silence.
--
-- Shape follows Panther's password-spray search, which counts DISTINCT targets
-- rather than raw attempts. Panther's version flags many distinct usernames
-- from one source. This flags many distinct hosts from one source. Same idea,
-- different axis: breadth, not depth.
--
-- The LEFT JOIN ... IS NULL idiom in `unanswered` is the standard SQL way to
-- ask "did the reply never happen", which is the whole question here.

-- Everything below is keyed on (capture, ip), never on ip alone.
--
-- That is not fussiness. The first version of this query grouped by source_ip
-- and reported a scan window of 98,949,825 seconds, which is a little over
-- three years. The cause: 192.168.1.46 appears in three different captures
-- recorded in 2017, 2017 and 2020. RFC 1918 addresses get reused constantly,
-- so the same private IP in two captures is almost never the same machine.
-- Grouping on the address alone silently welded three hosts into one.
--
-- Any corpus assembled from more than one capture has this problem. The fix
-- is cheap and the bug is invisible until a number looks absurd.
WITH outbound AS (
    SELECT
        capture,
        source_ip                       AS scanner,
        destination_ip                  AS target,
        destination_port                AS dport,
        COUNT(*)                        AS attempts,
        MIN(ts)                         AS first_seen,
        MAX(ts)                         AS last_seen
    FROM events
    WHERE destination_ip IS NOT NULL
      AND source_ip IS NOT NULL
    GROUP BY capture, source_ip, destination_ip, destination_port
),

-- A target "answered" if it ever sent anything back to the scanner, within
-- the same capture.
answered AS (
    SELECT DISTINCT
        e.capture,
        e.destination_ip AS scanner,
        e.source_ip      AS target
    FROM events e
    WHERE e.destination_ip IS NOT NULL
),

unanswered AS (
    SELECT
        o.capture,
        o.scanner,
        o.target,
        o.dport,
        o.attempts,
        o.first_seen,
        o.last_seen,
        CASE WHEN a.target IS NULL THEN 1 ELSE 0 END AS silent
    FROM outbound o
    LEFT JOIN answered a
      ON  a.capture = o.capture
      AND a.scanner = o.scanner
      AND a.target  = o.target
)

SELECT
    capture,
    scanner                                      AS source_ip,
    COUNT(DISTINCT target)                       AS distinct_targets,
    COUNT(DISTINCT dport)                        AS distinct_ports,
    SUM(attempts)                                AS total_attempts,
    SUM(silent)                                  AS silent_targets,
    ROUND(1.0 * SUM(silent) / COUNT(*), 3)       AS silent_ratio,
    ROUND(MAX(last_seen) - MIN(first_seen), 1)   AS window_s
FROM unanswered
GROUP BY capture, scanner
-- Three or more targets before this is a pattern rather than a connection.
HAVING COUNT(DISTINCT target) >= 3
ORDER BY silent_ratio DESC, distinct_targets DESC;
