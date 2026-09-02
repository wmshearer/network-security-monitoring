-- First contact: a destination this host has never talked to before.
--
-- Modelled on Panther's baseline-anomaly search, which builds a 30-day per-actor
-- baseline and then flags values absent from it. Panther uses ARRAY_AGG and
-- ARRAY_CONTAINS. SQLite has neither, so the same idea is expressed with
-- NOT IN over a subquery, which is the portable form.
--
-- The split point is the median timestamp of each capture rather than a fixed
-- date, because the captures were recorded years apart and a hardcoded date
-- would be meaningless across them.
--
-- This is a novelty check, not a rarity check. It asks "has this pair been
-- seen before in the baseline period", which is a different and more useful
-- question than "is this pair rare overall".

WITH capture_bounds AS (
    SELECT
        capture,
        MIN(ts)                       AS start_ts,
        MIN(ts) + (MAX(ts) - MIN(ts)) / 2.0 AS split_ts,
        MAX(ts)                       AS end_ts
    FROM events
    GROUP BY capture
),

-- What each host talked to during the first half of its capture.
baseline AS (
    SELECT DISTINCT
        e.capture,
        e.source_ip,
        e.destination_ip
    FROM events e
    JOIN capture_bounds b ON b.capture = e.capture
    WHERE e.ts < b.split_ts
      AND e.destination_ip IS NOT NULL
),

-- What each host talked to during the second half.
observed AS (
    SELECT
        e.capture,
        e.source_ip,
        e.destination_ip,
        COUNT(*)      AS packets,
        MIN(e.ts)     AS first_seen
    FROM events e
    JOIN capture_bounds b ON b.capture = e.capture
    WHERE e.ts >= b.split_ts
      AND e.destination_ip IS NOT NULL
    GROUP BY e.capture, e.source_ip, e.destination_ip
)

SELECT
    o.capture,
    o.source_ip,
    o.destination_ip                          AS new_destination,
    o.packets,
    datetime(o.first_seen, 'unixepoch')       AS first_seen_utc
FROM observed o
WHERE NOT EXISTS (
    SELECT 1 FROM baseline b
    WHERE b.capture        = o.capture
      AND b.source_ip      = o.source_ip
      AND b.destination_ip = o.destination_ip
)
  -- One packet to a new host is noise. Sustained conversation is a signal.
  AND o.packets >= 10
ORDER BY o.packets DESC;
