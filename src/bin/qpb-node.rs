use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use tiny_http::{Header, Method, Response, Server};

use qpb_consensus::node::chainparams::{
    compute_chain_id, compute_genesis_hash, load_chainparams, select_network,
};
use qpb_consensus::node::node::Node;
use qpb_consensus::node::rpc::handle_rpc;

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

    let node = Node::open_or_init(&args.chain, &args.datadir, args.no_pow)?;

    println!(
        "chain={} height={} tip={}",
        node.chain,
        node.height(),
        node.best_hash_hex()
    );

    if let Some(addr) = args.rpc_addr {
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
        let resp_body = {
            let mut node = shared.lock().unwrap();
            handle_rpc(&mut node, &body)
        };
        let response = Response::from_string(resp_body)
            .with_header(Header::from_bytes("Content-Type", "application/json").unwrap());
        let _ = request.respond(response);
    }
    Ok(())
}
