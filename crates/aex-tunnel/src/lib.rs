//! Tunnel providers for the Spize data plane.
//!
//! The tunnel layer gives a locally-bound HTTP server a public URL so
//! peers across the internet can reach it. Each provider is a different
//! way of achieving that:
//!
//! - [`CloudflareQuickTunnel`] — wraps `cloudflared tunnel --url …`.
//!   Zero-config but ephemeral URL (regenerated on every restart).
//! - [`StubTunnel`] — in-process no-op used by tests. Returns a fixed URL
//!   without starting any process.
//!
//! Later phases will add:
//! - `NamedTunnel` — persistent URL using Cloudflare named tunnels.
//! - `TailscaleTunnel` — funnel URL via Tailscale.

pub mod cloudflare;
pub mod error;
pub mod provider;
pub mod stub;
mod url_parser;

pub use cloudflare::CloudflareQuickTunnel;
pub use error::{TunnelError, TunnelResult};
pub use provider::{TunnelProvider, TunnelStatus};
pub use stub::StubTunnel;

#[cfg(test)]
pub use url_parser::extract_tunnel_url;
