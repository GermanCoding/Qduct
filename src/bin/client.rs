use clap::Parser;
use qduct::tunnel::Client;
use std::net::SocketAddr;
use tracing::log::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = ClientArgs::parse();
    info!(
        "Listening for incoming UDP packets on {}",
        args.local_source
    );
    let client = Client::try_new(args.local_source).await?;
    let tunnel = client.connect(args.remote).await?;
    info!("Connected! Forwarding data...");
    tunnel.run().await
}

#[derive(Debug, clap::Parser)]
struct ClientArgs {
    /// The address of the QUIC server (the other party)
    #[clap(long, short)]
    remote: SocketAddr,
    /// The address to receive data to forward on
    #[clap(long, short)]
    local_source: SocketAddr,
    #[clap(flatten)]
    common: qduct::CommonArgs,
}
