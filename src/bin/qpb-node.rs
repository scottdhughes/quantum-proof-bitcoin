use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tiny_http::{Header, Method, Response, Server};
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use qpb_consensus::constants::{
    DEFAULT_DEVNET_PORT, DEFAULT_MAINNET_PORT, DEFAULT_TESTNET_PORT, MAX_INBOUND_CONNECTIONS,
};
use qpb_consensus::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network,
};
use qpb_consensus::node::node::Node;
use qpb_consensus::node::p2p::{
    InboundConfig, InboundListener, OutboundConfig, OutboundManager, SyncOpts, sync_with_retries,
};
use qpb_consensus::node::rpc::{RpcAction, handle_rpc_action};
use qpb_consensus::node::rpc_limiter::RpcRateLimiter;

#[derive(Parser, Debug)]
#[command(
    name = "qpb-node",
    about = "QPB reference node (Phase 0A: genesis init + persistence)"
)]
struct Args {
    #[arg(long, default_value = "devnet")]
    chain: String,
    #[arg(long, default_value = "docs/chain/chainparams.json")]
    chainparams: PathBuf,
    #[arg(long, default_value = ".qpb")]
    datadir: PathBuf,
    #[arg(long)]
    rpc_addr: Option<String>,
    #[arg(long, default_value_t = false)]
    no_pow: bool,
    #[arg(
        long = "p2p-connect",
        value_parser = clap::builder::NonEmptyStringValueParser::new(),
        num_args = 0..,
        action = clap::ArgAction::Append
    )]
    p2p_connect: Option<Vec<String>>,
    #[arg(long, default_value_t = 30000)]
    p2p_deadline_ms: u64,
    #[arg(long, default_value_t = 3)]
    p2p_attempts: usize,
    #[arg(long, default_value_t = 250)]
    p2p_backoff_ms: u64,

    /// Enable inbound P2P connections.
    #[arg(long = "listen", default_value_t = false)]
    listen: bool,

    /// Address to bind for inbound connections (default: 0.0.0.0).
    #[arg(long = "bind", default_value = "0.0.0.0")]
    bind_addr: String,

    /// Port to listen on for inbound connections.
    /// Defaults: mainnet=8333, testnet=18333, devnet=28333.
    #[arg(long = "port")]
    p2p_port: Option<u16>,

    /// Maximum inbound connections to accept.
    #[arg(long = "maxinbound")]
    max_inbound: Option<usize>,

    /// RPC username for authentication.
    #[arg(long = "rpcuser")]
    rpc_user: Option<String>,

    /// RPC password for authentication.
    #[arg(long = "rpcpassword")]
    rpc_password: Option<String>,

    /// Maximum RPC requests per second per client (0 = unlimited).
    #[arg(long = "rpc-rate-limit", default_value_t = 100)]
    rpc_rate_limit: u32,
}

/// RPC authentication configuration.
#[derive(Clone)]
struct RpcAuth {
    /// Base64-encoded "user:password" for HTTP Basic Auth validation.
    expected_basic: String,
}

impl RpcAuth {
    fn new(user: &str, password: &str) -> Self {
        use base64::Engine;
        let credentials = format!("{}:{}", user, password);
        let expected_basic = base64::engine::general_purpose::STANDARD.encode(credentials);
        Self { expected_basic }
    }

    /// Validate an Authorization header value.
    /// Returns true if auth is valid, false otherwise.
    fn check(&self, auth_header: Option<&str>) -> bool {
        match auth_header {
            Some(value) => {
                if let Some(encoded) = value.strip_prefix("Basic ") {
                    encoded == self.expected_basic
                } else {
                    false
                }
            }
            None => false,
        }
    }
}

fn main() -> Result<()> {
    // Initialize structured logging with RUST_LOG env filter
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();
    let params = load_chainparams(&args.chainparams)?;
    let net = select_network(&params, &args.chain)?;
    let genesis = net
        .genesis
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("genesis missing for chain {}", args.chain))?;
    let header = &genesis.header;

    // Validate genesis hash and chain_id
    let computed_hash = compute_genesis_hash(header)?;
    let stored_hash =
        hex::decode(&genesis.block_hash_hex).context("decode stored genesis block hash")?;
    if computed_hash.as_ref() != stored_hash {
        anyhow::bail!("genesis block hash mismatch for {}", args.chain);
    }
    let computed_chain_id = compute_chain_id(header)?;
    let stored_chain_id = hex::decode(&genesis.chain_id_hex).context("decode stored chain id")?;
    if computed_chain_id.as_ref() != stored_chain_id {
        anyhow::bail!("genesis chain_id mismatch for {}", args.chain);
    }

    let mut node = Node::open_or_init(&args.chain, &args.datadir, args.no_pow)?;

    info!(
        chain = %node.chain,
        height = node.height(),
        tip = %node.best_hash_hex(),
        "node started"
    );

    // Gather peer addresses from multiple sources
    let mut peer_addrs: Vec<std::net::SocketAddr> = Vec::new();

    // 1. Manual --p2p-connect peers (highest priority)
    if let Some(peers) = args.p2p_connect.as_ref() {
        let manual_addrs: Vec<std::net::SocketAddr> = peers
            .iter()
            .filter_map(|s| s.parse::<std::net::SocketAddr>().ok())
            .collect();

        // Seed address manager with manual peers so OutboundManager can use them
        if !manual_addrs.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for addr in &manual_addrs {
                // services=1 (NODE_NETWORK) is a reasonable default
                node.addr_manager_mut().add(*addr, 1, now);
            }
        }

        peer_addrs.extend(manual_addrs);
    }

    // 2. DNS seeds (if no manual peers specified)
    if peer_addrs.is_empty() && !net.dns_seeds.is_empty() {
        use qpb_consensus::node::discovery::resolve_dns_seeds;
        let dns_addrs = resolve_dns_seeds(&net.dns_seeds, net.p2p_port);
        if !dns_addrs.is_empty() {
            info!(count = dns_addrs.len(), "resolved addresses from DNS seeds");

            // Seed address manager with DNS-resolved peers
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            for addr in &dns_addrs {
                // services=1 (NODE_NETWORK) is a reasonable default for DNS-resolved peers
                node.addr_manager_mut().add(*addr, 1, now);
            }

            peer_addrs.extend(dns_addrs);
        }
    }

    // Sync with discovered peers
    if !peer_addrs.is_empty() {
        let opts = SyncOpts {
            max_attempts_per_peer: args.p2p_attempts.max(1),
            initial_backoff_ms: args.p2p_backoff_ms,
            max_backoff_ms: 5_000,
            total_deadline_ms: args.p2p_deadline_ms,
        };
        sync_with_retries(&mut node, net, &peer_addrs, &opts)?;
    }

    // Start inbound listener if enabled
    let node_arc: Option<Arc<Mutex<Node>>>;

    if args.listen {
        let mut inbound_listener: Option<InboundListener>;
        // Determine port based on chain
        let port = args.p2p_port.unwrap_or(match args.chain.as_str() {
            "mainnet" => DEFAULT_MAINNET_PORT,
            "testnet" => DEFAULT_TESTNET_PORT,
            _ => DEFAULT_DEVNET_PORT,
        });

        // Parse bind address
        let bind_addr: SocketAddr = format!("{}:{}", args.bind_addr, port)
            .parse()
            .context("invalid bind address")?;

        // Get network magic (hex string to bytes)
        let magic: [u8; 4] = hex::decode(&net.p2p_magic)
            .context("invalid p2p_magic hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("p2p_magic must be 4 bytes"))?;

        // Initialize peer manager
        let peer_manager = node.init_peer_manager();

        // Create listener config
        let config = InboundConfig {
            bind_addr,
            magic,
            max_inbound: args.max_inbound.unwrap_or(MAX_INBOUND_CONNECTIONS),
        };

        // Bind the listener
        let mut listener = InboundListener::bind(config)?;
        info!(%bind_addr, "p2p listening");

        // Wrap node for sharing
        let shared = Arc::new(Mutex::new(node));
        node_arc = Some(Arc::clone(&shared));

        // Start accepting connections
        listener.start(
            Arc::clone(&shared),
            Arc::clone(&peer_manager),
            |peer_id, version| {
                info!(
                    peer_id,
                    version = version.version,
                    height = version.start_height,
                    "peer connected"
                );
            },
        );

        inbound_listener = Some(listener);

        // Start outbound connection manager
        let outbound_config = OutboundConfig {
            magic,
            target_outbound: 8,
            local_addr: Some(bind_addr),
            maintenance_interval_ms: 30_000,
        };
        let mut outbound_manager = OutboundManager::new(outbound_config);
        outbound_manager.start(Arc::clone(&shared), Arc::clone(&peer_manager));

        // Create shutdown flag
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // If RPC is also enabled, run it
        if let Some(ref addr) = args.rpc_addr {
            let rpc_auth = create_rpc_auth(&args)?;
            let rpc_limiter = create_rpc_limiter(&args);
            start_rpc_server_shared(
                addr.clone(),
                node_arc.clone().unwrap(),
                Arc::clone(&shutdown_flag),
                rpc_auth,
                rpc_limiter,
            )?;
        }

        // Install signal handler
        let shutdown_for_signal = Arc::clone(&shutdown_flag);
        ctrlc::set_handler(move || {
            info!("shutdown signal received");
            shutdown_for_signal.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl+C handler");

        info!("press Ctrl+C to stop the node");

        // Wait for shutdown signal
        while !shutdown_flag.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }

        // Graceful shutdown sequence
        debug!("initiating graceful shutdown");

        // 1. Stop outbound manager
        debug!("stopping outbound manager");
        outbound_manager.shutdown();

        // 2. Stop accepting new connections
        if let Some(ref listener) = inbound_listener {
            debug!("stopping inbound listener");
            listener.shutdown();
        }

        // 3. Wait for outbound manager to finish
        outbound_manager.join();
        debug!("outbound manager stopped");

        // 4. Wait for listener thread to finish
        if let Some(listener) = inbound_listener.take() {
            listener.join();
            debug!("listener stopped");
        }

        // 5. Save node state
        debug!("saving node state");
        if let Some(ref node_arc) = node_arc {
            let node = node_arc.lock().unwrap();
            if let Err(e) = node.save() {
                warn!(error = %e, "failed to save node state");
            }
        }

        info!("shutdown complete");
        return Ok(());
    } else if let Some(ref addr) = args.rpc_addr {
        // No listening, just RPC server
        let rpc_auth = create_rpc_auth(&args)?;
        let rpc_limiter = create_rpc_limiter(&args);
        start_rpc_server(addr.clone(), node, rpc_auth, rpc_limiter)?;
    }

    Ok(())
}

/// Create RPC auth configuration from CLI args.
/// Returns None if no auth is configured (allows unauthenticated access).
fn create_rpc_auth(args: &Args) -> Result<Option<RpcAuth>> {
    match (&args.rpc_user, &args.rpc_password) {
        (Some(user), Some(password)) => {
            if user.is_empty() || password.is_empty() {
                anyhow::bail!("--rpcuser and --rpcpassword must not be empty");
            }
            Ok(Some(RpcAuth::new(user, password)))
        }
        (Some(_), None) => {
            anyhow::bail!("--rpcpassword is required when --rpcuser is specified");
        }
        (None, Some(_)) => {
            anyhow::bail!("--rpcuser is required when --rpcpassword is specified");
        }
        (None, None) => {
            // No auth configured - warn but allow
            warn!("RPC server running without authentication (--rpcuser/--rpcpassword not set)");
            Ok(None)
        }
    }
}

/// Create RPC rate limiter from CLI args.
/// Returns None if rate limiting is disabled (--rpc-rate-limit=0).
fn create_rpc_limiter(args: &Args) -> Option<Arc<RpcRateLimiter>> {
    if args.rpc_rate_limit == 0 {
        warn!("RPC rate limiting disabled (--rpc-rate-limit=0)");
        None
    } else {
        // Use 2x rate as bucket capacity for burst allowance
        let bucket_capacity = args.rpc_rate_limit.saturating_mul(2);
        Some(Arc::new(RpcRateLimiter::new(
            bucket_capacity,
            args.rpc_rate_limit,
        )))
    }
}

/// Format Prometheus metrics for the /metrics endpoint.
fn format_prometheus_metrics(node: &Node, inbound: usize, outbound: usize) -> String {
    let mut metrics = String::with_capacity(2048);
    let mempool_info = node.mempool_info();

    // Node info (gauge with labels)
    metrics.push_str("# HELP qpb_node_info Node information\n");
    metrics.push_str("# TYPE qpb_node_info gauge\n");
    metrics.push_str(&format!(
        "qpb_node_info{{chain=\"{}\"}} 1\n",
        node.chain
    ));

    // Block height
    metrics.push_str("# HELP qpb_block_height Current block height\n");
    metrics.push_str("# TYPE qpb_block_height gauge\n");
    metrics.push_str(&format!("qpb_block_height {}\n", node.height()));

    // Peer connections
    metrics.push_str("# HELP qpb_peers_inbound Number of inbound peer connections\n");
    metrics.push_str("# TYPE qpb_peers_inbound gauge\n");
    metrics.push_str(&format!("qpb_peers_inbound {}\n", inbound));

    metrics.push_str("# HELP qpb_peers_outbound Number of outbound peer connections\n");
    metrics.push_str("# TYPE qpb_peers_outbound gauge\n");
    metrics.push_str(&format!("qpb_peers_outbound {}\n", outbound));

    metrics.push_str("# HELP qpb_peers_total Total peer connections\n");
    metrics.push_str("# TYPE qpb_peers_total gauge\n");
    metrics.push_str(&format!("qpb_peers_total {}\n", inbound + outbound));

    // Mempool stats
    metrics.push_str("# HELP qpb_mempool_size Number of transactions in mempool\n");
    metrics.push_str("# TYPE qpb_mempool_size gauge\n");
    metrics.push_str(&format!("qpb_mempool_size {}\n", mempool_info.size));

    metrics.push_str("# HELP qpb_mempool_bytes Total size of mempool in bytes\n");
    metrics.push_str("# TYPE qpb_mempool_bytes gauge\n");
    metrics.push_str(&format!("qpb_mempool_bytes {}\n", mempool_info.bytes));

    metrics.push_str("# HELP qpb_mempool_fees_total Total fees in mempool (satoshis)\n");
    metrics.push_str("# TYPE qpb_mempool_fees_total gauge\n");
    metrics.push_str(&format!("qpb_mempool_fees_total {}\n", mempool_info.total_fee));

    // Orphan transactions
    metrics.push_str("# HELP qpb_orphan_txs Number of orphan transactions\n");
    metrics.push_str("# TYPE qpb_orphan_txs gauge\n");
    metrics.push_str(&format!("qpb_orphan_txs {}\n", node.orphan_count()));

    // UTXO set size
    metrics.push_str("# HELP qpb_utxo_count Number of unspent transaction outputs\n");
    metrics.push_str("# TYPE qpb_utxo_count gauge\n");
    metrics.push_str(&format!("qpb_utxo_count {}\n", node.utxo_count()));

    metrics
}

fn start_rpc_server(
    addr: String,
    node: Node,
    auth: Option<RpcAuth>,
    rate_limiter: Option<Arc<RpcRateLimiter>>,
) -> Result<()> {
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    info!(
        %addr,
        auth_enabled = auth.is_some(),
        rate_limit_enabled = rate_limiter.is_some(),
        "rpc listening"
    );
    let shared = Arc::new(Mutex::new(node));
    for mut request in server.incoming_requests() {
        let shared = Arc::clone(&shared);

        // Handle health endpoint (no auth required for load balancers/monitoring)
        if request.method() == &Method::Get && request.url() == "/health" {
            let node = shared.lock().unwrap();
            let (inbound, outbound) = node.peer_count();
            let health_response = format!(
                r#"{{"status":"ok","chain":"{}","height":{},"tip":"{}","peers":{{"inbound":{},"outbound":{}}}}}"#,
                node.chain,
                node.height(),
                node.best_hash_hex(),
                inbound,
                outbound
            );
            let _ = request.respond(
                Response::from_string(health_response)
                    .with_header(Header::from_bytes("Content-Type", "application/json").unwrap()),
            );
            continue;
        }

        // Handle Prometheus metrics endpoint (no auth required for scraping)
        if request.method() == &Method::Get && request.url() == "/metrics" {
            let node = shared.lock().unwrap();
            let (inbound, outbound) = node.peer_count();
            let metrics = format_prometheus_metrics(&node, inbound, outbound);
            let _ = request.respond(
                Response::from_string(metrics).with_header(
                    Header::from_bytes("Content-Type", "text/plain; version=0.0.4").unwrap(),
                ),
            );
            continue;
        }

        if request.method() != &Method::Post || request.url() != "/rpc" {
            let _ = request.respond(Response::from_string("not found").with_status_code(404));
            continue;
        }

        // Check rate limit if enabled
        if let Some(ref limiter) = rate_limiter {
            let client_ip = request
                .remote_addr()
                .map(|addr| addr.ip())
                .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
            if !limiter.try_consume(client_ip) {
                let _ = request.respond(
                    Response::from_string(r#"{"error":"Too Many Requests"}"#)
                        .with_status_code(429)
                        .with_header(Header::from_bytes("Retry-After", "1").unwrap()),
                );
                continue;
            }
        }

        // Check authentication if enabled
        if let Some(ref rpc_auth) = auth {
            let auth_header = request
                .headers()
                .iter()
                .find(|h| {
                    h.field
                        .as_str()
                        .as_str()
                        .eq_ignore_ascii_case("authorization")
                })
                .map(|h| h.value.as_str());
            if !rpc_auth.check(auth_header) {
                let _ = request.respond(
                    Response::from_string(r#"{"error":"Unauthorized"}"#)
                        .with_status_code(401)
                        .with_header(
                            Header::from_bytes("WWW-Authenticate", "Basic realm=\"qpb-rpc\"")
                                .unwrap(),
                        ),
                );
                continue;
            }
        }

        let mut body = String::new();
        if let Err(e) = request.as_reader().read_to_string(&mut body) {
            let _ = request
                .respond(Response::from_string(format!("read error: {}", e)).with_status_code(400));
            continue;
        }
        let (resp_body, action) = {
            let mut node = shared.lock().unwrap();
            handle_rpc_action(&mut node, &body)
        };
        let response = Response::from_string(resp_body)
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
        let _ = request.respond(response);
        if matches!(action, RpcAction::Stop) {
            // Save mempool before shutdown
            let node = shared.lock().unwrap();
            if let Err(e) = node.save() {
                warn!(error = %e, "failed to save node state");
            }
            break;
        }
    }
    Ok(())
}

/// Start RPC server with a shared node (runs in background thread).
fn start_rpc_server_shared(
    addr: String,
    shared: Arc<Mutex<Node>>,
    shutdown: Arc<AtomicBool>,
    auth: Option<RpcAuth>,
    rate_limiter: Option<Arc<RpcRateLimiter>>,
) -> Result<()> {
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    info!(
        %addr,
        auth_enabled = auth.is_some(),
        rate_limit_enabled = rate_limiter.is_some(),
        "rpc listening"
    );

    std::thread::spawn(move || {
        loop {
            // Check shutdown flag
            if shutdown.load(Ordering::SeqCst) {
                break;
            }

            // Use recv_timeout for periodic shutdown checks
            let mut request = match server.recv_timeout(Duration::from_millis(500)) {
                Ok(Some(req)) => req,
                Ok(None) => continue, // Timeout, check shutdown again
                Err(_) => break,
            };

            let shared = Arc::clone(&shared);

            // Handle health endpoint (no auth required for load balancers/monitoring)
            if request.method() == &Method::Get && request.url() == "/health" {
                let node = shared.lock().unwrap();
                let (inbound, outbound) = node.peer_count();
                let health_response = format!(
                    r#"{{"status":"ok","chain":"{}","height":{},"tip":"{}","peers":{{"inbound":{},"outbound":{}}}}}"#,
                    node.chain,
                    node.height(),
                    node.best_hash_hex(),
                    inbound,
                    outbound
                );
                let _ = request.respond(
                    Response::from_string(health_response)
                        .with_header(Header::from_bytes("Content-Type", "application/json").unwrap()),
                );
                continue;
            }

            // Handle Prometheus metrics endpoint (no auth required for scraping)
            if request.method() == &Method::Get && request.url() == "/metrics" {
                let node = shared.lock().unwrap();
                let (inbound, outbound) = node.peer_count();
                let metrics = format_prometheus_metrics(&node, inbound, outbound);
                let _ = request.respond(
                    Response::from_string(metrics).with_header(
                        Header::from_bytes("Content-Type", "text/plain; version=0.0.4").unwrap(),
                    ),
                );
                continue;
            }

            if request.method() != &Method::Post || request.url() != "/rpc" {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
                continue;
            }

            // Check rate limit if enabled
            if let Some(ref limiter) = rate_limiter {
                let client_ip = request
                    .remote_addr()
                    .map(|addr| addr.ip())
                    .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
                if !limiter.try_consume(client_ip) {
                    let _ = request.respond(
                        Response::from_string(r#"{"error":"Too Many Requests"}"#)
                            .with_status_code(429)
                            .with_header(Header::from_bytes("Retry-After", "1").unwrap()),
                    );
                    continue;
                }
            }

            // Check authentication if enabled
            if let Some(ref rpc_auth) = auth {
                let auth_header = request
                    .headers()
                    .iter()
                    .find(|h| {
                        h.field
                            .as_str()
                            .as_str()
                            .eq_ignore_ascii_case("authorization")
                    })
                    .map(|h| h.value.as_str());
                if !rpc_auth.check(auth_header) {
                    let _ = request.respond(
                        Response::from_string(r#"{"error":"Unauthorized"}"#)
                            .with_status_code(401)
                            .with_header(
                                Header::from_bytes("WWW-Authenticate", "Basic realm=\"qpb-rpc\"")
                                    .unwrap(),
                            ),
                    );
                    continue;
                }
            }

            let mut body = String::new();
            if let Err(e) = request.as_reader().read_to_string(&mut body) {
                let _ = request.respond(
                    Response::from_string(format!("read error: {}", e)).with_status_code(400),
                );
                continue;
            }
            let (resp_body, action) = {
                let mut node = shared.lock().unwrap();
                handle_rpc_action(&mut node, &body)
            };
            let response = Response::from_string(resp_body)
                .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
            let _ = request.respond(response);

            // Handle RPC actions
            match action {
                RpcAction::Stop => {
                    // Signal shutdown for other components
                    shutdown.store(true, Ordering::SeqCst);
                    break;
                }
                RpcAction::BroadcastBlock(block_hash) => {
                    // Queue block for relay to all peers (sender_id=0 for locally-mined)
                    let node = shared.lock().unwrap();
                    if let Some(pm) = node.peer_manager() {
                        pm.queue_block_relay(0, block_hash);
                        debug!(?block_hash, "queued block for broadcast");
                    }
                }
                RpcAction::BroadcastTransaction(txid) => {
                    // Queue transaction for relay to all peers (sender_id=0 for local tx)
                    let node = shared.lock().unwrap();
                    if let Some(pm) = node.peer_manager() {
                        pm.queue_relay(0, txid);
                        debug!(?txid, "queued transaction for broadcast");
                    }
                }
                RpcAction::Continue => {}
            }
        }
    });

    Ok(())
}
