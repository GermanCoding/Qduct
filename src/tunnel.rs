use bytes::BytesMut;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use quinn::{rustls, Connection, Endpoint, ServerConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::SetOnce;
use tracing::debug;
use tracing::log::info;

const BUF_SIZE: usize = 1500;
const MAX_STREAMS: u16 = 1024;
const SERVER_NAME: &str = "Qduct";

pub struct Server {
    endpoint: Endpoint,
    udp_server: UdpSocket,
    udp_destination: SocketAddr,
    pub certificate: CertificateDer<'static>,
}

impl Server {
    pub async fn try_new(
        quic_addr: SocketAddr,
        udp_destination: SocketAddr,
    ) -> anyhow::Result<Self> {
        let bind_ip = if udp_destination.ip().is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let udp_server = UdpSocket::bind((bind_ip, 0)).await?;
        let keypair = rcgen::generate_simple_self_signed(vec![SERVER_NAME.into()])?;
        let certificate = CertificateDer::from(keypair.cert);
        let priv_key = PrivatePkcs8KeyDer::from(keypair.signing_key.serialize_der());
        let mut config =
            ServerConfig::with_single_cert([certificate.clone()].to_vec(), priv_key.into())?;
        let transport = Arc::get_mut(&mut config.transport).unwrap(/* Infallible*/);
        transport.max_concurrent_uni_streams(MAX_STREAMS.into());
        transport.keep_alive_interval(Some(Duration::from_secs(25)));
        transport.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
        let endpoint = Endpoint::server(config, quic_addr)?;
        Ok(Self {
            endpoint,
            udp_server,
            udp_destination,
            certificate,
        })
    }

    pub async fn accept(self) -> anyhow::Result<UdpTunnel> {
        let udp_server = self.udp_server;
        let endpoint = self.endpoint;
        let quic_addr = endpoint.local_addr()?;
        info!("Waiting for incoming QUIC connection on {quic_addr}...");
        let incoming = endpoint.accept().await.unwrap(/* Infallible */);
        debug!(
            "Got an incoming QUIC connection from {}...",
            incoming.remote_address()
        );
        let connection = incoming.accept()?.await?;
        let tunnel = UdpTunnel {
            udp_server,
            udp_destination: SetOnce::new(),
            endpoint,
            connection,
        };
        tunnel.udp_destination.set(self.udp_destination)?;
        Ok(tunnel)
    }
}

pub struct Client {
    udp_server: UdpSocket,
    endpoint: Endpoint,
}

impl Client {
    pub async fn try_new(udp_sink: SocketAddr) -> anyhow::Result<Self> {
        let udp_server = UdpSocket::bind(udp_sink).await?;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(BypassCertificateVerifier::new())
            .with_no_client_auth();
        let mut quic_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(config)?));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(Duration::from_secs(120).try_into()?));
        transport_config.max_concurrent_uni_streams(MAX_STREAMS.into());
        quic_config.transport_config(Arc::from(transport_config));
        let mut endpoint = Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into())?;
        endpoint.set_default_client_config(quic_config);
        Ok(Self {
            udp_server,
            endpoint,
        })
    }

    pub async fn connect(self, remote_server: SocketAddr) -> anyhow::Result<UdpTunnel> {
        let endpoint = self.endpoint;
        let udp_server = self.udp_server;
        info!("QUIC client connecting to {remote_server}...");
        let connection = endpoint.connect(remote_server, SERVER_NAME)?.await?;
        let tunnel = UdpTunnel {
            udp_server,
            udp_destination: SetOnce::new(),
            endpoint,
            connection,
        };
        Ok(tunnel)
    }
}

pub struct UdpTunnel {
    udp_server: UdpSocket,
    udp_destination: SetOnce<SocketAddr>,
    #[allow(dead_code)]
    endpoint: Endpoint,
    connection: Connection,
}

impl UdpTunnel {
    pub async fn run(self) -> anyhow::Result<()> {
        let udp_server_1 = Arc::new(self.udp_server);
        let udp_server_2 = Arc::clone(&udp_server_1);
        let udp_destination_1 = Arc::new(self.udp_destination);
        let udp_destination_2 = Arc::clone(&udp_destination_1);
        let connection_1 = Arc::new(self.connection);
        let connection_2 = Arc::clone(&connection_1);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let udp_receive: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::task::spawn(async move {
                let mut destination_set = udp_destination_1.initialized();
                loop {
                    let mut buf = BytesMut::with_capacity(BUF_SIZE);
                    let (_size, addr) = udp_server_1.recv_buf_from(&mut buf).await?;
                    if !destination_set {
                        destination_set = true;
                        udp_destination_1.set(addr).ok();
                    }
                    sender.send(buf.freeze())?;
                }
            });
        let quic_send: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::task::spawn(async move {
                loop {
                    let data = receiver
                        .recv()
                        .await
                        .ok_or(anyhow::anyhow!("channel closed"))?;
                    let mut outbound = connection_1.open_uni().await?;
                    outbound.write_all(&data).await?;
                }
            });
        let quic_receive: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::task::spawn(async move {
                loop {
                    let mut inbound = connection_2.accept_uni().await?;
                    let data = inbound.read_to_end(BUF_SIZE).await?;
                    if let Some(destination) = udp_destination_2.get() {
                        udp_server_2.send_to(&data, destination).await?;
                    }
                }
            });
        tokio::select! {
            udp_receive = udp_receive => udp_receive??,
            quic_send = quic_send => quic_send??,
            quic_receive = quic_receive => quic_receive??
        }
        Ok(())
    }
}

#[derive(Debug)]
struct BypassCertificateVerifier(Arc<rustls::crypto::CryptoProvider>);

impl BypassCertificateVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }
}

impl ServerCertVerifier for BypassCertificateVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use tokio::task::JoinHandle;
    use tokio::time::Instant;

    const UNSPECIFIED_ADDR: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));

    struct TestConfig {
        client_task: JoinHandle<()>,
        server_task: JoinHandle<()>,
        server_udp_socket: UdpSocket,
        client_udp_socket: UdpSocket,
    }

    async fn setup_client_and_server() -> TestConfig {
        let udp_server = UdpSocket::bind(UNSPECIFIED_ADDR).await.unwrap();
        let udp_server_addr = udp_server.local_addr().unwrap();
        let server = Server::try_new(UNSPECIFIED_ADDR, udp_server_addr)
            .await
            .unwrap();
        udp_server
            .connect((
                Ipv4Addr::LOCALHOST,
                server.udp_server.local_addr().unwrap().port(),
            ))
            .await
            .unwrap();
        let server_addr = server.endpoint.local_addr().unwrap();
        let server_task = tokio::task::spawn(async move {
            let tunnel = server.accept().await.unwrap();
            tunnel.run().await.unwrap();
        });
        let client = Client::try_new(UNSPECIFIED_ADDR).await.unwrap();
        let client_socket = UdpSocket::bind(UNSPECIFIED_ADDR).await.unwrap();
        client_socket
            .connect((
                Ipv4Addr::LOCALHOST,
                client.udp_server.local_addr().unwrap().port(),
            ))
            .await
            .unwrap();
        let client_task = tokio::task::spawn(async move {
            let tunnel = client.connect(server_addr).await.unwrap();
            tunnel.run().await.unwrap();
        });
        TestConfig {
            client_task,
            server_task,
            server_udp_socket: udp_server,
            client_udp_socket: client_socket,
        }
    }

    #[tokio::test]
    pub async fn client_to_server_test() {
        let config = setup_client_and_server().await;
        config
            .client_udp_socket
            .send("Hello server!".as_bytes())
            .await
            .unwrap();
        let mut buf = [0; 1024];
        let len = config.server_udp_socket.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], "Hello server!".as_bytes());
    }

    #[tokio::test]
    pub async fn server_to_client_test() {
        let config = setup_client_and_server().await;
        // Need an initial message for the client to learn the sender's address
        config
            .client_udp_socket
            .send("Initial message".as_bytes())
            .await
            .unwrap();
        config
            .server_udp_socket
            .send("Hello client!".as_bytes())
            .await
            .unwrap();
        let mut buf = [0; 1024];
        let len = config.client_udp_socket.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], "Hello client!".as_bytes());
    }
}
