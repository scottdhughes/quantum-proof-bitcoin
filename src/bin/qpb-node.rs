use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tiny_http::{Header, Method, Response, Server};

use qpb_consensus::constants::{
    DEFAULT_DEVNET_PORT, DEFAULT_MAINNET_PORT, DEFAULT_TESTNET_PORT, MAX_INBOUND_CONNECTIONS,
};
use qpb_consensus::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network,
};
use qpb_consensus::node::node::Node;
use qpb_consensus::node::p2p::{InboundConfig, InboundListener, SyncOpts, sync_with_retries};
use qpb_consensus::node::rpc::{RpcAction, handle_rpc_action};

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
}

fn main() -> Result<()> {
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

    println!(
        "chain={} height={} tip={}",
        node.chain,
        node.height(),
        node.best_hash_hex()
    );

    // Gather peer addresses from multiple sources
    let mut peer_addrs: Vec<std::net::SocketAddr> = Vec::new();

    // 1. Manual --p2p-connect peers (highest priority)
    if let Some(peers) = args.p2p_connect.as_ref() {
        peer_addrs.extend(
            peers
                .iter()
                .filter_map(|s| s.parse::<std::net::SocketAddr>().ok()),
        );
    }

    // 2. DNS seeds (if no manual peers specified)
    if peer_addrs.is_empty() && !net.dns_seeds.is_empty() {
        use qpb_consensus::node::discovery::resolve_dns_seeds;
        let dns_addrs = resolve_dns_seeds(&net.dns_seeds, net.p2p_port);
        if !dns_addrs.is_empty() {
            println!("resolved {} addresses from DNS seeds", dns_addrs.len());
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
        println!("p2p listening on {}", bind_addr);

        // Wrap node for sharing
        let shared = Arc::new(Mutex::new(node));
        node_arc = Some(Arc::clone(&shared));

        // Start accepting connections
        listener.start(Arc::clone(&shared), peer_manager, |peer_id, version| {
            println!(
                "peer {} connected: version={}, height={}",
                peer_id, version.version, version.start_height
            );
        });

        inbound_listener = Some(listener);

        // Create shutdown flag
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // If RPC is also enabled, run it
        if let Some(addr) = args.rpc_addr {
            start_rpc_server_shared(addr, node_arc.clone().unwrap(), Arc::clone(&shutdown_flag))?;
        }

        // Install signal handler
        let shutdown_for_signal = Arc::clone(&shutdown_flag);
        ctrlc::set_handler(move || {
            eprintln!("\nShutdown signal received...");
            shutdown_for_signal.store(true, Ordering::SeqCst);
        })
        .expect("Error setting Ctrl+C handler");

        println!("Press Ctrl+C to stop the node");

        // Wait for shutdown signal
        while !shutdown_flag.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));
        }

        // Graceful shutdown sequence
        eprintln!("Initiating graceful shutdown...");

        // 1. Stop accepting new connections
        if let Some(ref listener) = inbound_listener {
            eprintln!("Stopping inbound listener...");
            listener.shutdown();
        }

        // 2. Wait for listener thread to finish
        if let Some(listener) = inbound_listener.take() {
            listener.join();
            eprintln!("Listener stopped");
        }

        // 3. Save node state
        eprintln!("Saving node state...");
        if let Some(ref node_arc) = node_arc {
            let node = node_arc.lock().unwrap();
            if let Err(e) = node.save() {
                eprintln!("Warning: failed to save node state: {}", e);
            }
        }

        eprintln!("Shutdown complete");
        return Ok(());
    } else if let Some(addr) = args.rpc_addr {
        // No listening, just RPC server
        start_rpc_server(addr, node)?;
    }

    Ok(())
}

fn start_rpc_server(addr: String, node: Node) -> Result<()> {
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    println!("rpc listening on http://{}", addr);
    let shared = Arc::new(Mutex::new(node));
    for mut request in server.incoming_requests() {
        let shared = Arc::clone(&shared);
        if request.method() != &Method::Post || request.url() != "/rpc" {
            let _ = request.respond(Response::from_string("not found").with_status_code(404));
            continue;
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
                eprintln!("warning: failed to save node state: {}", e);
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
) -> Result<()> {
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    println!("rpc listening on http://{}", addr);

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
            if request.method() != &Method::Post || request.url() != "/rpc" {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
                continue;
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
            if matches!(action, RpcAction::Stop) {
                // Signal shutdown for other components
                shutdown.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    Ok(())
}
