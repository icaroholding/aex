//! `aex-cli` — operator-facing command-line for the Agent Exchange Protocol.
//!
//! Two subcommands ship at v2.0 GA:
//!
//! - **`debug resolve <handle>`** — runs the resolver chain end-to-end
//!   for a single handle and prints each step with timing. Operators
//!   use this to triage "why won't this agent_id resolve?" reports
//!   without grepping logs.
//! - **`qr <handle>`** — prints an ASCII QR code of the handle plus a
//!   `vCard` URL line, for sharing your AEX identity at conferences,
//!   on business cards, or via NFC tap. Designed to be a 30-second
//!   onboarding aid.
//!
//! Both are deliberately small and avoid network IO by default — they
//! exercise the local `aex-identity` + `aex-core` layers and surface
//! issues without dragging in a real control plane. Network-aware
//! debugging (`did:web` fetch traces) is a v2.1 follow-up.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "aex-cli",
    about = "Command-line utility for AEX (Agent Exchange Protocol)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Debug helpers (resolve, decode, inspect).
    #[command(subcommand)]
    Debug(DebugCmd),

    /// Print an ASCII QR code of an AEX agent_id.
    Qr {
        /// The handle to encode (e.g. `did:web:acme.com#fatture`).
        handle: String,
    },
}

#[derive(Subcommand, Debug)]
enum DebugCmd {
    /// Inspect a handle through the local resolver chain.
    ///
    /// For `did:key:...` ids the decode is offline and immediate.
    /// For `did:web` / `did:ethr` / `did:spize` the v2.0 CLI prints a
    /// notice that network resolution is staged for v2.1 — implement
    /// once the production ResolverChain is wired with real providers.
    Resolve {
        /// The handle to resolve (e.g. `did:key:z6Mk...`).
        handle: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Debug(DebugCmd::Resolve { handle }) => match cmd_debug_resolve(&handle) {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("error: {}", msg);
                ExitCode::FAILURE
            }
        },
        Command::Qr { handle } => match cmd_qr(&handle) {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("error: {}", msg);
                ExitCode::FAILURE
            }
        },
    }
}

fn cmd_debug_resolve(handle: &str) -> Result<(), String> {
    use std::time::Instant;

    use aex_core::{AgentId, IdScheme};
    use aex_identity::DidKeyProvider;

    let t_start = Instant::now();
    println!("→ parsing handle …");
    let agent_id = AgentId::new(handle.to_string()).map_err(|e| format!("{}", e))?;
    let t_parse = t_start.elapsed();
    println!(
        "  ✓ AgentId::new ok            [{} µs]",
        t_parse.as_micros()
    );

    let scheme = agent_id.scheme();
    println!("  ✓ scheme dispatch → {:?}", scheme);

    if let Some(uri) = agent_id.as_did_uri() {
        println!("  ✓ parsed as W3C DID URI:");
        println!("      method            = {}", uri.method);
        println!("      method_specific_id = {}", uri.method_specific_id);
        if let Some(f) = uri.fragment {
            println!("      fragment          = #{}", f);
        }
    } else {
        println!("  • legacy (non-DID) AgentId — wire-v1 only");
    }

    match scheme {
        IdScheme::DidKey => {
            println!("→ decoding did:key inline …");
            let t = Instant::now();
            let vk = DidKeyProvider::decode_pubkey(&agent_id).map_err(|e| format!("{}", e))?;
            let elapsed = t.elapsed();
            println!(
                "  ✓ Ed25519 public key extracted [{} µs]",
                elapsed.as_micros()
            );
            // Hex-print the public key for operator-side comparison.
            let mut hex = String::with_capacity(64);
            for b in vk.as_bytes() {
                hex.push_str(&format!("{:02x}", b));
            }
            println!("  public_key (hex) = {}", hex);
        }
        IdScheme::DidWeb | IdScheme::DidEthr | IdScheme::DidSpize | IdScheme::SpizeNative => {
            println!(
                "  ℹ network resolution for {:?} is staged for v2.1 — \
                 ResolverChain wiring in this CLI is pending.",
                scheme
            );
        }
        IdScheme::Unknown => {
            println!("  ⚠ unrecognised scheme; no resolver available");
        }
    }

    let total = t_start.elapsed();
    println!("→ done                          [total {} µs]", total.as_micros());
    Ok(())
}

fn cmd_qr(handle: &str) -> Result<(), String> {
    use aex_core::AgentId;
    use qrcode::render::unicode::Dense1x2;
    use qrcode::{EcLevel, QrCode};

    // Validate first; emitting a QR of a bogus handle is wasteful and
    // misleading (recipients would scan it, try to use it, and fail
    // mysteriously).
    let agent_id = AgentId::new(handle.to_string()).map_err(|e| format!("{}", e))?;

    let code = QrCode::with_error_correction_level(agent_id.as_str().as_bytes(), EcLevel::M)
        .map_err(|e| format!("qr encode failed: {}", e))?;
    let rendered = code
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build();

    println!("{}", rendered);
    println!("Handle: {}", agent_id.as_str());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_top_level_args() {
        let cli = Cli::try_parse_from([
            "aex-cli",
            "debug",
            "resolve",
            "did:key:zabc",
        ])
        .unwrap();
        match cli.command {
            Command::Debug(DebugCmd::Resolve { handle }) => {
                assert_eq!(handle, "did:key:zabc")
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_qr_args() {
        let cli =
            Cli::try_parse_from(["aex-cli", "qr", "did:web:acme.com#fatture"]).unwrap();
        match cli.command {
            Command::Qr { handle } => assert_eq!(handle, "did:web:acme.com#fatture"),
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn missing_subcommand_errors() {
        let res = Cli::try_parse_from(["aex-cli"]);
        assert!(res.is_err());
    }

    #[test]
    fn qr_validates_handle() {
        let err = cmd_qr("").unwrap_err();
        assert!(err.contains("agent_id") || err.contains("empty"));
    }

    #[test]
    fn debug_resolve_handles_did_key_offline() {
        // Construct a valid did:key:z6Mk... via the DidKeyProvider.
        use aex_core::IdentityProvider;
        use aex_identity::DidKeyProvider;
        let provider = DidKeyProvider::generate().unwrap();
        let handle = provider.agent_id().as_str().to_string();
        cmd_debug_resolve(&handle).expect("did:key decode must succeed offline");
    }

    #[test]
    fn debug_resolve_rejects_empty_handle() {
        let err = cmd_debug_resolve("").unwrap_err();
        assert!(err.contains("agent_id") || err.contains("empty"));
    }

    #[test]
    fn qr_renders_for_did_key() {
        use aex_core::IdentityProvider;
        use aex_identity::DidKeyProvider;
        let provider = DidKeyProvider::generate().unwrap();
        let handle = provider.agent_id().as_str().to_string();
        cmd_qr(&handle).expect("QR rendering must succeed for a valid did:key");
    }
}
