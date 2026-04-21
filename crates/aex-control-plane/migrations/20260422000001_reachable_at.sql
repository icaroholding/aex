-- Sprint 2 (v1.3.0-beta.1): transport plurality.
--
-- Adds `reachable_at JSONB` to `transfers`, carrying a list of endpoints the
-- recipient can try in sender-ranked order (ADR-0001, ADR-0013). The column
-- coexists with the legacy `tunnel_url TEXT` during Sprint 2 per ADR-0036
-- (coordinated rollout + 30-day dual-parse grace). A later migration in
-- Sprint 2 week 3 will drop `tunnel_url` after the wire bump to v2.
--
-- Shape of each element (per crates/aex-core/src/endpoint.rs):
--   { "kind": "cloudflare_quick|cloudflare_named|iroh|tailscale_funnel|frp|...",
--     "url":  "https://... | iroh:NodeID@relay:port",
--     "priority": 0,
--     "health_hint_unix": 1700000000 }  -- optional
--
-- Existing rows with a `tunnel_url` are backfilled to a single-element
-- reachable_at list of kind `cloudflare_quick` so legacy transfers stay
-- queryable through the new path.

ALTER TABLE transfers
    ADD COLUMN reachable_at JSONB NOT NULL DEFAULT '[]'::jsonb;

UPDATE transfers
SET reachable_at = jsonb_build_array(
    jsonb_build_object(
        'kind',     'cloudflare_quick',
        'url',      tunnel_url,
        'priority', 0
    )
)
WHERE tunnel_url IS NOT NULL
  AND reachable_at = '[]'::jsonb;
