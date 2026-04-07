//! DIF Universal Resolver driver for the `did:ndn` DID method.
//!
//! Implements the DIF DID Resolution HTTP binding:
//! <https://w3c-ccg.github.io/did-resolution/#bindings-https>
//!
//! # Usage
//!
//! ```sh
//! did-ndn-driver --port 8080
//! ```
//!
//! # DIF Universal Resolver integration
//!
//! Add to `uni-resolver-web/src/main/resources/application.yml`:
//!
//! ```yaml
//! - pattern: "^did:ndn:.+"
//!   url: "http://did-ndn-driver:8080/1.0/identifiers/"
//! ```
//!
//! Then submit a PR to <https://github.com/decentralized-identity/universal-resolver>.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use ndn_did::{DidError, UniversalResolver};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

/// DIF DID Resolution result envelope.
///
/// <https://w3c-ccg.github.io/did-resolution/#did-resolution-result>
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DidResolutionResult {
    #[serde(rename = "@context")]
    context: String,
    did_document: Value,
    did_resolution_metadata: ResolutionMetadata,
    did_document_metadata: DocumentMetadata,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ResolutionMetadata {
    content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct DocumentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<String>,
}

struct AppState {
    resolver: UniversalResolver,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "did_ndn_driver=info".to_string())
                .as_str(),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state = Arc::new(AppState {
        resolver: UniversalResolver::new(),
    });

    let app = Router::new()
        .route("/1.0/identifiers/{did}", get(resolve_did))
        .route("/health", get(health))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("did-ndn-driver listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn resolve_did(
    Path(did): Path<String>,
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<DidResolutionResult>) {
    info!(did = %did, "resolving DID");

    match state.resolver.resolve(&did).await {
        Ok(doc) => {
            let doc_value = serde_json::to_value(&doc).unwrap_or(Value::Null);
            (
                StatusCode::OK,
                Json(DidResolutionResult {
                    context: "https://w3id.org/did-resolution/v1".to_string(),
                    did_document: doc_value,
                    did_resolution_metadata: ResolutionMetadata {
                        content_type: "application/did+ld+json".to_string(),
                        error: None,
                        error_message: None,
                    },
                    did_document_metadata: DocumentMetadata::default(),
                }),
            )
        }
        Err(e) => {
            warn!(did = %did, error = %e, "DID resolution failed");
            let (status, message) = map_error(&e);
            (
                status,
                Json(DidResolutionResult {
                    context: "https://w3id.org/did-resolution/v1".to_string(),
                    did_document: Value::Null,
                    did_resolution_metadata: ResolutionMetadata {
                        content_type: "application/did+ld+json".to_string(),
                        error: Some(error_type(&e).to_string()),
                        error_message: Some(message),
                    },
                    did_document_metadata: DocumentMetadata::default(),
                }),
            )
        }
    }
}

async fn health() -> &'static str {
    "ok"
}

fn map_error(e: &DidError) -> (StatusCode, String) {
    match e {
        DidError::InvalidDid(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
        DidError::UnsupportedMethod(method) => (
            StatusCode::NOT_IMPLEMENTED,
            format!("DID method '{method}' not supported"),
        ),
        DidError::NotFound(did) => (StatusCode::NOT_FOUND, format!("DID not found: {did}")),
        DidError::Resolution(msg) => (StatusCode::BAD_GATEWAY, msg.clone()),
        DidError::InvalidDocument(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
    }
}

fn error_type(e: &DidError) -> &'static str {
    match e {
        DidError::InvalidDid(_) => "invalidDid",
        DidError::UnsupportedMethod(_) => "methodNotSupported",
        DidError::NotFound(_) => "notFound",
        DidError::Resolution(_) => "internalError",
        DidError::InvalidDocument(_) => "invalidDidDocument",
    }
}
