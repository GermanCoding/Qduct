use clap::Parser;
use qduct::tunnel::{CertificateByteWords, Client};
use std::net::SocketAddr;
use tokio::signal;
use tracing::log::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = ClientArgs::parse();
    info!(
        "Listening for incoming UDP packets on {}",
        args.local_source
    );
    let client = Client::try_new(args.local_source).await?;
    let words = client.certificate.get_bytewords();
    info!("Your certificate words are: {words}");
    loop {
        let tunnel = client.connect(args.remote).await?;
        info!("Connected! Forwarding data...");
        tokio::select! {
            abort = signal::ctrl_c() => {
                if let Err(err) = abort {
                    error!("Unable to listen for shutdown signal, shutting down: {}", err);
                }
                info!("Shutting down running connection...");
                client.shutdown().await;
                break;
            },
            result = tunnel.run() => {
                match result {
                    Ok(()) => {
                        info!("Connection closed.");
                    }
                    Err(e) => {
                        warn!("Connection failed: {e:#}");
                    }
                }
            }
        }
    }
    Ok(())
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
