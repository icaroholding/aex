//! Wire-v2 control-plane routes (ADR-0042).
//!
//! Mounted under `/v2` by [`crate::public_routes`]. At v2.0 beta we
//! ship:
//!
//! - `GET /v2/capabilities` — JSON document advertising the wire
//!   versions and capability bits this control plane supports.
//! - `POST /v2/intents` — STUB at v2.0 beta. Returns
//!   `501 Not Implemented` with a structured body pointing operators
//!   to the rollout plan (ADR-0043). The handler is wired so dual-wire
//!   negotiation works (clients can probe v2 support without errors)
//!   while the full intent-verification path lands in v2.0 GA.
//!
//! # Why ship a stub now
//!
//! Capability negotiation (ADR-0043) needs the v2 endpoints to *exist*
//! before SDKs can advertise v2 support to peers. Shipping the
//! capability advertiser first decouples the dual-wire rollout from
//! the full intent verification — the latter requires DB schema work
//! that happens in the next sprint.

pub mod capabilities;
pub mod intents;

use axum::Router;

use crate::AppState;

/// Build the `/v2` subtree.
pub fn router() -> Router<AppState> {
    Router::new()
        .merge(capabilities::router())
        .merge(intents::router())
}
