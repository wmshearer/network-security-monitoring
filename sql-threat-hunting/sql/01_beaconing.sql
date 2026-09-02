-- Beaconing: find callbacks that arrive on a schedule.
--
-- Malware that phones home tends to do it on a timer. People do not. So the
-- signal is not volume, it is regularity: the gap between one connection and
-- the next barely changes.
--
-- Shape borrowed from Panther's published VPC-flow beaconing search, which
-- chains CTEs rather than trying to do it in one pass. Panther's version keys
-- on "few connections per day, sustained across many days". This one keys on
-- the variance of the gaps, because the captures here are hours long rather
-- than weeks long, so day-counting has nothing to count.
--
-- The measure is mean absolute deviation over the mean gap. Call it jitter.
-- A perfect timer scores 0. Human traffic scores high because people are
-- irregular. Using MAD rather than standard deviation keeps one long pause
-- from dominating the score.
--
-- Note the two-stage structure. The first CTE computes gaps with LAG. The
-- second aggregates them. The final SELECT joins back to the gaps to measure
-- deviation against each pair's own mean. Doing that last part as a
-- correlated subquery instead makes SQLite re-scan per row, which took this
-- query from 0.16 seconds to over two minutes. That was a real mistake made
-- while writing this file, not a hypothetical.

WITH gaps AS (
    SELECT
        source_ip                AS src,
        destination_ip           AS dst,
        destination_port         AS dport,
        ts - LAG(ts) OVER (
            PARTITION BY source_ip, destination_ip, destination_port
            ORDER BY ts
        )                        AS gap
    FROM events
    WHERE destination_ip IS NOT NULL
),

-- Gaps under half a second are almost always packets inside one exchange,
-- not separate callbacks. Dropping them stops a single busy TCP conversation
-- from looking like a metronome.
real_gaps AS (
    SELECT * FROM gaps WHERE gap IS NOT NULL AND gap > 0.5
),

pair_stats AS (
    SELECT
        src, dst, dport,
        COUNT(*)  AS intervals,
        AVG(gap)  AS mean_gap
    FROM real_gaps
    GROUP BY src, dst, dport
    -- Fewer than eight intervals is not a pattern, it is a coincidence.
    HAVING COUNT(*) >= 8
)

SELECT
    s.src                                              AS source_ip,
    s.dst                                              AS destination_ip,
    s.dport                                            AS destination_port,
    s.intervals,
    ROUND(s.mean_gap, 1)                               AS mean_interval_s,
    ROUND(AVG(ABS(g.gap - s.mean_gap)), 2)             AS mad_s,
    ROUND(AVG(ABS(g.gap - s.mean_gap)) / s.mean_gap, 4) AS jitter
FROM pair_stats s
JOIN real_gaps g
  ON  g.src   = s.src
  AND g.dst   = s.dst
  AND g.dport = s.dport
GROUP BY s.src, s.dst, s.dport
-- Under 0.15 means the gaps sit within about 15 percent of their own mean.
-- That is a schedule.
HAVING jitter < 0.15
ORDER BY jitter ASC;
