use base256::{Encode, PgpEncode};
use bytes::BytesMut;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use quinn::rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use quinn::rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, Error, SignatureScheme,
};
use quinn::{rustls, Connection, Endpoint, ServerConfig, VarInt};
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::log::{info, warn};

const BUF_SIZE: usize = 1500;
const MAX_STREAMS: u16 = 1024;
const CERT_NAME: &str = "Qduct";
const COMPARE_HASH_BYTES: usize = 8;

fn new_keypair() -> anyhow::Result<(CertificateDer<'static>, PrivatePkcs8KeyDer<'static>)> {
    let keypair = rcgen::generate_simple_self_signed(vec![CERT_NAME.into()])?;
    let certificate = CertificateDer::from(keypair.cert);
    let priv_key = PrivatePkcs8KeyDer::from(keypair.signing_key.serialize_der());
    Ok((certificate, priv_key))
}

pub trait CertificateByteWords {
    fn get_bytewords(&self) -> String;
}

impl CertificateByteWords for CertificateDer<'_> {
    fn get_bytewords(&self) -> String {
        let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
        ctx.update(self.as_ref());
        let cert_hash = ctx.finish();
        let hash_truncated = cert_hash.as_ref()[..COMPARE_HASH_BYTES].bytes();
        let encoded = Encode::<_, PgpEncode<_>>::encode(hash_truncated);
        let mut words = String::new();
        for word in encoded {
            if !words.is_empty() {
                words.push(' ');
            }
            words.push_str(word.unwrap());
        }
        words
    }
}

pub struct Server {
    endpoint: Endpoint,
    udp_server: Arc<UdpSocket>,
    udp_destination: SocketAddr,
    pub certificate: CertificateDer<'static>,
    shutdown: CancellationToken,
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
        let udp_server = Arc::new(UdpSocket::bind((bind_ip, 0)).await?);
        let (certificate, priv_key) = new_keypair()?;
        let crypto_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(InteractiveCertificateVerifier::new())
            .with_single_cert([certificate.clone()].to_vec(), priv_key.into())?;
        let mut config =
            ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(crypto_config)?));
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
            shutdown: CancellationToken::new(),
        })
    }

    pub async fn accept(&self) -> anyhow::Result<UdpTunnel> {
        let udp_server = self.udp_server.clone();
        let endpoint = &self.endpoint;
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
            preset_udp_destination: Some(self.udp_destination),
            connection,
            shutdown: self.shutdown.child_token(),
        };
        Ok(tunnel)
    }

    pub async fn shutdown(self) {
        self.shutdown.cancel();
        self.endpoint.close(VarInt::from_u32(0), &[]);
        self.endpoint.wait_idle().await;
    }
}

pub struct Client {
    udp_server: Arc<UdpSocket>,
    endpoint: Endpoint,
    pub certificate: CertificateDer<'static>,
    shutdown: CancellationToken,
}

impl Client {
    pub async fn try_new(udp_sink: SocketAddr) -> anyhow::Result<Self> {
        let udp_server = Arc::new(UdpSocket::bind(udp_sink).await?);
        let (certificate, priv_key) = new_keypair()?;
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(InteractiveCertificateVerifier::new())
            .with_client_auth_cert([certificate.clone()].to_vec(), priv_key.into())?;
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
            certificate,
            shutdown: CancellationToken::new(),
        })
    }

    pub async fn connect(&self, remote_server: SocketAddr) -> anyhow::Result<UdpTunnel> {
        let endpoint = &self.endpoint;
        let udp_server = self.udp_server.clone();
        info!("QUIC client connecting to {remote_server}...");
        let connection = endpoint.connect(remote_server, CERT_NAME)?.await?;
        let tunnel = UdpTunnel {
            udp_server,
            preset_udp_destination: None,
            connection,
            shutdown: self.shutdown.child_token(),
        };
        Ok(tunnel)
    }

    pub async fn shutdown(self) {
        self.shutdown.cancel();
        self.endpoint.close(VarInt::from_u32(0), &[]);
        self.endpoint.wait_idle().await;
    }
}

pub struct UdpTunnel {
    udp_server: Arc<UdpSocket>,
    preset_udp_destination: Option<SocketAddr>,
    connection: Connection,
    shutdown: CancellationToken,
}

impl UdpTunnel {
    pub async fn run(self) -> anyhow::Result<()> {
        let shutdown = self.shutdown;
        let udp_server_1 = self.udp_server;
        let udp_server_2 = Arc::clone(&udp_server_1);
        let (new_udp_destination_sender, mut new_udp_destination_receiver) =
            tokio::sync::mpsc::channel(10);
        let connection_1 = Arc::new(self.connection);
        let connection_2 = Arc::clone(&connection_1);
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();

        if let Some(initial_destination) = self.preset_udp_destination {
            new_udp_destination_sender.try_send(initial_destination)?;
        }

        let udp_receive: tokio::task::JoinHandle<anyhow::Result<()>> =
            tokio::task::spawn(async move {
                let mut last_destination = None;
                loop {
                    let mut buf = BytesMut::with_capacity(BUF_SIZE);
                    let (_size, addr) = udp_server_1.recv_buf_from(&mut buf).await?;
                    if Some(addr) != last_destination {
                        last_destination = Some(addr);
                        new_udp_destination_sender.try_send(addr).ok();
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
                let mut destination = None;
                loop {
                    tokio::select! {
                        biased;
                        new_destination = new_udp_destination_receiver.recv() => {
                            destination = new_destination;
                        },
                        accept_uni = connection_2.accept_uni() => {
                            let mut inbound = accept_uni?;
                            let data = inbound.read_to_end(BUF_SIZE).await?;
                             if let Some(destination) = destination {
                                udp_server_2.send_to(&data, destination).await?;
                            }
                        }
                    }
                }
            });

        let abort_udp_receive = udp_receive.abort_handle();
        let abort_quic_send = quic_send.abort_handle();
        let abort_quic_receive = quic_receive.abort_handle();

        tokio::select! {
            udp_receive = udp_receive => udp_receive??,
            quic_send = quic_send => quic_send??,
            quic_receive = quic_receive => quic_receive??,
            _ = shutdown.cancelled() => {
                abort_udp_receive.abort();
                abort_quic_send.abort();
                abort_quic_receive.abort();
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct InteractiveCertificateVerifier(Arc<rustls::crypto::CryptoProvider>);

impl InteractiveCertificateVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self(Arc::new(rustls::crypto::ring::default_provider())))
    }

    #[cfg(not(test))]
    fn verify(certificate: &CertificateDer<'_>) -> anyhow::Result<()> {
        let words = certificate.get_bytewords();
        println!("Please verify the certificate words with your peer:");
        let confirmed = inquire::Confirm::new(&words).with_default(false).prompt()?;
        if confirmed {
            Ok(())
        } else {
            anyhow::bail!("Verification denied by user")
        }
    }

    #[cfg(test)]
    fn verify(_certificate: &CertificateDer<'_>) -> anyhow::Result<()> {
        // Disable certificate verification in tests
        Ok(())
    }
}

impl ServerCertVerifier for InteractiveCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        match InteractiveCertificateVerifier::verify(end_entity) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(e) => {
                warn!("Server certificate not verified: {e:#}");
                Err(Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }
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

impl ClientCertVerifier for InteractiveCertificateVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        match InteractiveCertificateVerifier::verify(end_entity) {
            Ok(()) => Ok(ClientCertVerified::assertion()),
            Err(e) => {
                warn!("Client certificate not verified: {e:#}");
                Err(Error::InvalidCertificate(
                    rustls::CertificateError::UnknownIssuer,
                ))
            }
        }
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
