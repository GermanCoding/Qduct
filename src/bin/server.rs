use clap::Parser;
use qduct::tunnel::{CertificateByteWords, Server};
use std::net::SocketAddr;
use tokio::signal;
use tracing::log::{error, info, warn};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = ServerArgs::parse();
    info!("Sending received packets to {}", args.local_sink);
    let server = Server::try_new(args.server, args.local_sink, args.common).await?;
    let words = server.certificate.get_bytewords();
    info!("Your certificate words are: {words}");
    loop {
        let tunnel = server.accept().await?;
        info!("Connected! Forwarding data...");
        tokio::select! {
            abort = signal::ctrl_c() => {
                if let Err(err) = abort {
                    error!("Unable to listen for shutdown signal, shutting down: {}", err);
                }
                info!("Shutting down running connection...");
                server.shutdown().await;
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
