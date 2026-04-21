use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;

use crate::AppState;

#[derive(Serialize)]
struct HealthBody {
    status: &'static str,
    service: &'static str,
    version: &'static str,
}

async fn healthz() -> Json<HealthBody> {
    Json(HealthBody {
        status: "ok",
        service: "aex-control-plane",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Serialize)]
struct PublicKeyBody {
    algorithm: &'static str,
    public_key_hex: String,
}

/// Publishes the control-plane's Ed25519 public key so data-plane
/// servers can verify tickets without an out-of-band key exchange.
async fn public_key(State(state): State<AppState>) -> Result<Json<PublicKeyBody>, StatusCode> {
    let signer = state.signer.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(PublicKeyBody {
        algorithm: "ed25519",
        public_key_hex: signer.public_key_hex(),
    }))
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/public-key", get(public_key))
}
