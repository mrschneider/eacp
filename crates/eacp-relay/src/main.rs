//! EACP Push Relay Daemon executable.

mod constants;
mod deadlock;
mod frame;
mod relay;

use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, UnixListener};
use tracing::{error, info};

use crate::relay::{handle_connection, RelayConfig, RelayState};

#[derive(Parser, Debug)]
#[command(author, version, about = "EACP Microkernel Push Relay Daemon (Rust)", long_about = None)]
struct Args {
    #[arg(long, default_value = "0.0.0.0", help = "Listen host")]
    host: String,

    #[arg(long, default_value_t = 8990, help = "Listen port")]
    port: u16,

    #[arg(long, help = "Listen on Unix domain socket path")]
    socket: Option<String>,

    #[arg(long, default_value_t = 1000, help = "Max offline push queue per agent")]
    max_queue: usize,

    #[arg(long, default_value_t = 16, help = "Max frame payload size in MB")]
    max_payload_mb: usize,

    #[arg(long, default_value_t = 90.0, help = "Heartbeat timeout in seconds")]
    heartbeat_timeout: f64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    let config = RelayConfig {
        max_push_queue: args.max_queue,
        max_payload_size: args.max_payload_mb * 1024 * 1024,
        heartbeat_timeout_s: args.heartbeat_timeout,
    };

    let state = Arc::new(RelayState::new(config));

    // Spawn periodic heartbeat reaper task
    let reaper_state = Arc::clone(&state);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            reaper_state.prune_timed_out_agents().await;
        }
    });

    if let Some(unix_path) = args.socket {
        if std::path::Path::new(&unix_path).exists() {
            let _ = std::fs::remove_file(&unix_path);
        }
        let listener = UnixListener::bind(&unix_path)?;
        info!("EACP Relay listening on unix socket {}...", unix_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    tokio::spawn(handle_connection(stream, Arc::clone(&state)));
                }
                Err(e) => {
                    error!("Error accepting unix connection: {}", e);
                }
            }
        }
    } else {
        let addr = format!("{}:{}", args.host, args.port);
        let listener = TcpListener::bind(&addr).await?;
        info!("EACP Relay listening on {}...", addr);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    info!("Incoming connection from {}", peer_addr);
                    tokio::spawn(handle_connection(stream, Arc::clone(&state)));
                }
                Err(e) => {
                    error!("Error accepting tcp connection: {}", e);
                }
            }
        }
    }
}
