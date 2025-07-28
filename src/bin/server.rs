use clap::Parser;
use qduct::tunnel::Server;
use std::net::SocketAddr;
use tracing::log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = ServerArgs::parse();
    info!("Sending received packets to {}", args.local_sink);
    let server = Server::try_new(args.server, args.local_sink).await?;
    let tunnel = server.accept().await?;
    info!("Connected! Forwarding data...");
    tunnel.run().await
}

#[derive(Debug, clap::Parser)]
struct ServerArgs {
    /// The listen address of this QUIC server
    #[clap(long, short = 'S')]
    server: SocketAddr,
    /// The address to forward received data to
    #[clap(long, short = 's')]
    local_sink: SocketAddr,
    #[clap(flatten)]
    common: qduct::CommonArgs,
}
