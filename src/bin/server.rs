use clap::Parser;
use qduct::tunnel::Server;
use std::net::SocketAddr;
use tracing::log::{info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = ServerArgs::parse();
    info!("Sending received packets to {}", args.local_sink);
    let server = Server::try_new(args.server, args.local_sink).await?;
    loop {
        let tunnel = server.accept().await?;
        info!("Connected! Forwarding data...");
        match tunnel.run().await {
            Ok(()) => {
                info!("Connection closed.");
            }
            Err(e) => {
                warn!("Connection failed: {e:#}");
            }
        }
    }
}

#[derive(Debug, clap::Parser)]
struct ServerArgs {
    /// The listen address of this QUIC server
    #[clap(long, short)]
    server: SocketAddr,
    /// The address to forward received data to
    #[clap(long, short)]
    local_sink: SocketAddr,
    #[clap(flatten)]
    common: qduct::CommonArgs,
}
