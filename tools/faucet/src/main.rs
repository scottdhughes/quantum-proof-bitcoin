//! QPB Testnet Faucet
//!
//! A simple HTTP faucet that dispenses testnet coins via the QPB node RPC.
//!
//! Environment variables:
//! - QPB_RPC_URL: Node RPC endpoint (default: http://127.0.0.1:38335/rpc)
//! - QPB_RPC_USER: RPC username (default: rpcuser)
//! - QPB_RPC_PASS: RPC password (default: rpcpass)
//! - FAUCET_PAYOUT_SATS: Amount to send per request in sats (default: 100000000 = 1 QPB)
//! - FAUCET_RATE_LIMIT_SECS: Cooldown per IP in seconds (default: 3600 = 1 hour)
//! - FAUCET_PORT: Port to listen on (default: 8080)

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

/// Application state shared across handlers
struct AppState {
    /// RPC client configuration
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    /// Faucet configuration
    payout_sats: u64,
    rate_limit_secs: u64,
    /// IP rate limiting: IP -> last request time
    rate_limits: RwLock<HashMap<String, Instant>>,
}

/// Request body for faucet endpoint
#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

/// Response body for faucet endpoint
#[derive(Serialize)]
struct FaucetResponse {
    txid: String,
    amount_sats: u64,
}

/// Error response
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    rpc_url: String,
}

/// JSON-RPC request structure
#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u32,
    method: &'static str,
    params: serde_json::Value,
}

/// JSON-RPC response structure
#[derive(Deserialize)]
struct RpcResponse {
    result: Option<serde_json::Value>,
    error: Option<RpcError>,
}

#[derive(Deserialize)]
struct RpcError {
    message: String,
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "qpb_faucet=info,tower_http=info".into()),
        )
        .init();

    // Load configuration from environment
    let rpc_url = env::var("QPB_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:38335/rpc".into());
    let rpc_user = env::var("QPB_RPC_USER").unwrap_or_else(|_| "rpcuser".into());
    let rpc_pass = env::var("QPB_RPC_PASS").unwrap_or_else(|_| "rpcpass".into());
    let payout_sats: u64 = env::var("FAUCET_PAYOUT_SATS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000_000); // 1 QPB
    let rate_limit_secs: u64 = env::var("FAUCET_RATE_LIMIT_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3600); // 1 hour
    let port: u16 = env::var("FAUCET_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);

    info!(
        rpc_url = %rpc_url,
        payout_sats = payout_sats,
        rate_limit_secs = rate_limit_secs,
        "Starting QPB faucet"
    );

    let state = Arc::new(AppState {
        rpc_url,
        rpc_user,
        rpc_pass,
        payout_sats,
        rate_limit_secs,
        rate_limits: RwLock::new(HashMap::new()),
    });

    // Build router
    let app = Router::new()
        .route("/faucet", post(faucet_handler))
        .route("/health", get(health_handler))
        .layer(CorsLayer::permissive())
        .with_state(state);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}

/// Health check endpoint
async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        rpc_url: state.rpc_url.clone(),
    })
}

/// Faucet endpoint - dispenses testnet coins
async fn faucet_handler(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<FaucetRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let client_ip = addr.ip().to_string();

    // Check rate limit
    {
        let rate_limits = state.rate_limits.read().await;
        if let Some(last_request) = rate_limits.get(&client_ip) {
            let elapsed = last_request.elapsed();
            let cooldown = Duration::from_secs(state.rate_limit_secs);
            if elapsed < cooldown {
                let remaining = cooldown - elapsed;
                warn!(
                    ip = %client_ip,
                    remaining_secs = remaining.as_secs(),
                    "Rate limited"
                );
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: format!(
                            "Rate limited. Try again in {} seconds.",
                            remaining.as_secs()
                        ),
                    }),
                ));
            }
        }
    }

    // Validate address (basic check - must start with qpb for devnet/testnet)
    if !req.address.starts_with("qpb") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid address: must be a QPB testnet address".into(),
            }),
        ));
    }

    // Call sendtoaddress RPC
    let rpc_req = RpcRequest {
        jsonrpc: "2.0",
        id: 1,
        method: "sendtoaddress",
        params: serde_json::json!([req.address, state.payout_sats]),
    };

    let client = reqwest::Client::new();
    let response = client
        .post(&state.rpc_url)
        .basic_auth(&state.rpc_user, Some(&state.rpc_pass))
        .json(&rpc_req)
        .send()
        .await
        .map_err(|e| {
            error!(error = %e, "RPC request failed");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    error: format!("RPC connection failed: {}", e),
                }),
            )
        })?;

    let rpc_resp: RpcResponse = response.json().await.map_err(|e| {
        error!(error = %e, "Failed to parse RPC response");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Failed to parse RPC response".into(),
            }),
        )
    })?;

    // Check for RPC error
    if let Some(err) = rpc_resp.error {
        error!(error = %err.message, "RPC error");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("RPC error: {}", err.message),
            }),
        ));
    }

    // Extract txid from result
    let txid = rpc_resp
        .result
        .and_then(|v| v.as_str().map(String::from))
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "No txid in RPC response".into(),
                }),
            )
        })?;

    // Update rate limit
    {
        let mut rate_limits = state.rate_limits.write().await;
        rate_limits.insert(client_ip.clone(), Instant::now());
    }

    info!(
        ip = %client_ip,
        address = %req.address,
        txid = %txid,
        amount_sats = state.payout_sats,
        "Dispensed coins"
    );

    Ok(Json(FaucetResponse {
        txid,
        amount_sats: state.payout_sats,
    }))
}
