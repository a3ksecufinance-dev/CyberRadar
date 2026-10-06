-- ═══════════════════════════════════════════════════════════════════════════
-- 000037 — Record what a route actually costs an attacker
--
-- Every edge carries a traversal weight — attack complexity plus privileges
-- required — and the walk accumulates it, but nothing kept it. A scenario's
-- "shortest path" was the fewest hops, so a one-hop route requiring an admin
-- credential and a remote exploit ranked ahead of a three-hop route over open
-- shares. Hops are not effort.
--
-- total_cost is that accumulated weight per route; cheapest_path_cost is the
-- smallest across a scenario — the weighted shortest path, which is what
-- "how exposed are we" actually asks.
-- ═══════════════════════════════════════════════════════════════════════════

ALTER TABLE attack_paths
    ADD COLUMN IF NOT EXISTS total_cost DOUBLE PRECISION NOT NULL DEFAULT 0;

COMMENT ON COLUMN attack_paths.total_cost IS
    'Sum of the traversal weights of this route''s edges. Lower means less work for an attacker.';

ALTER TABLE attack_scenarios
    ADD COLUMN IF NOT EXISTS cheapest_path_cost DOUBLE PRECISION;

COMMENT ON COLUMN attack_scenarios.cheapest_path_cost IS
    'Total cost of the weighted shortest route this scenario found. NULL when it found none.';

-- critical_path held the hop count of the LONGEST route and called it the most
-- critical one. It now holds the hop count of the highest-scoring route — the
-- one an attacker would actually take. Existing rows carry the old meaning, so
-- they are cleared rather than left to be misread; the next run recomputes them.
UPDATE attack_scenarios SET critical_path = NULL WHERE critical_path IS NOT NULL;

COMMENT ON COLUMN attack_scenarios.critical_path IS
    'Hop count of the highest-scoring route found, not the longest one.';
