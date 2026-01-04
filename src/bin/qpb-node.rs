use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use tiny_http::{Header, Method, Response, Server};

use qpb_consensus::constants::{DEFAULT_DEVNET_PORT, DEFAULT_MAINNET_PORT, DEFAULT_TESTNET_PORT, MAX_INBOUND_CONNECTIONS};
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

    // Optional outbound P2P sync: try peers in order until one succeeds.
    if let Some(peers) = args.p2p_connect.as_ref() {
        let params = load_chainparams(&args.chainparams)?;
        let net = select_network(&params, &args.chain)?;
        let addrs: Vec<std::net::SocketAddr> =
            peers.iter().filter_map(|s| s.parse().ok()).collect();
        if addrs.is_empty() {
            anyhow::bail!("no valid p2p peers provided");
        }
        let opts = SyncOpts {
            max_attempts_per_peer: args.p2p_attempts.max(1),
            initial_backoff_ms: args.p2p_backoff_ms,
            max_backoff_ms: 5_000,
            total_deadline_ms: args.p2p_deadline_ms,
        };
        sync_with_retries(&mut node, net, &addrs, &opts)?;
    }

    // Start inbound listener if enabled
    let mut inbound_listener: Option<InboundListener> = None;
    let node_arc: Option<Arc<Mutex<Node>>>;

    if args.listen {
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
        listener.start(
            Arc::clone(&shared),
            peer_manager,
            |peer_id, version| {
                println!(
                    "peer {} connected: version={}, height={}",
                    peer_id, version.version, version.start_height
                );
            },
        );

        inbound_listener = Some(listener);

        // If RPC is also enabled, run it
        if let Some(addr) = args.rpc_addr {
            start_rpc_server_shared(addr, node_arc.clone().unwrap())?;
        }

        // Wait for shutdown signal (Ctrl+C)
        println!("Press Ctrl+C to stop the node");
        std::thread::park(); // Block forever until interrupted
    } else if let Some(addr) = args.rpc_addr {
        // No listening, just RPC server
        start_rpc_server(addr, node)?;
    }

    // Clean shutdown of listener if running
    if let Some(listener) = inbound_listener {
        listener.shutdown();
        listener.join();
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
fn start_rpc_server_shared(addr: String, shared: Arc<Mutex<Node>>) -> Result<()> {
    let server = Server::http(&addr).map_err(|e| anyhow::anyhow!("bind {}: {}", addr, e))?;
    println!("rpc listening on http://{}", addr);

    std::thread::spawn(move || {
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
    });

    Ok(())
}
