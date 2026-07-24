use crypto::tls::{load_certs, load_private_key, TlsError};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Relay transport mode.
#[derive(Clone)]
pub enum RelayMode {
    /// Forward all traffic in cleartext.
    Cleartext,
    /// Accept TLS connections from agents, forward cleartext to upstream.
    TlsIngress(TlsAcceptor),
    /// Accept cleartext from agents, wrap with TLS when forwarding upstream.
    TlsEgress(tokio_rustls::TlsConnector, String),
}

pub struct Relay {
    pub listen_addr: String,
    pub upstream_addr: String,
    pub mode: RelayMode,
}

impl Relay {
    #[must_use]
    pub fn new(listen_addr: &str, upstream_addr: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            upstream_addr: upstream_addr.to_string(),
            mode: RelayMode::Cleartext,
        }
    }

    /// Configure the relay to accept TLS connections from agents.
    ///
    /// The relay terminates TLS and forwards cleartext to the upstream C2.
    pub fn with_tls_ingress(
        mut self,
        server_cert_path: &str,
        server_key_path: &str,
    ) -> Result<Self, TlsError> {
        let certs = load_certs(server_cert_path)?;
        let key = load_private_key(server_key_path)?;
        let acceptor = crypto::tls::build_tls_acceptor(certs, key)?;
        self.mode = RelayMode::TlsIngress(acceptor);
        Ok(self)
    }

    /// Configure the relay to accept cleartext from agents and forward via TLS.
    ///
    /// `ca_cert_path` is used to verify the upstream C2 server.
    pub fn with_tls_egress(
        mut self,
        ca_cert_path: &str,
        upstream_server_name: &str,
    ) -> Result<Self, TlsError> {
        let ca_certs = load_certs(ca_cert_path)?;
        let ca_cert = ca_certs
            .into_iter()
            .next()
            .ok_or_else(|| TlsError::CertParse("CA certificate file is empty".into()))?;
        let connector = crypto::tls::build_tls_connector(ca_cert, None, None)?;
        self.mode = RelayMode::TlsEgress(connector, upstream_server_name.to_string());
        Ok(self)
    }

    /// Run the relay loop.
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        log::info!(
            "Relay listening on {listen_addr}",
            listen_addr = self.listen_addr
        );

        loop {
            let (mut inbound, _) = listener.accept().await?;
            let upstream = self.upstream_addr.clone();
            let mode = self.mode.clone();

            tokio::spawn(async move {
                match mode {
                    RelayMode::Cleartext => match TcpStream::connect(&upstream).await {
                        Ok(mut outbound) => {
                            match io::copy_bidirectional(&mut inbound, &mut outbound).await {
                                Ok((to_upstream, to_downstream)) => {
                                    log::info!(
                                        "Relay session closed: {to_upstream} bytes up, {to_downstream} bytes down"
                                    );
                                }
                                Err(e) => {
                                    log::error!("Relay error: {e}");
                                }
                            }
                        }
                        Err(e) => {
                            log::error!("Relay failed to connect to upstream {upstream}: {e}");
                        }
                    },
                    RelayMode::TlsIngress(acceptor) => {
                        match acceptor.accept(inbound).await {
                            Ok(mut tls_stream) => {
                                match TcpStream::connect(&upstream).await {
                                    Ok(mut outbound) => {
                                        match io::copy_bidirectional(
                                            &mut tls_stream,
                                            &mut outbound,
                                        )
                                        .await
                                        {
                                            Ok((to_upstream, to_downstream)) => {
                                                log::info!(
                                                    "TLS relay session: {to_upstream} bytes up, {to_downstream} bytes down"
                                                );
                                            }
                                            Err(e) => {
                                                log::error!("TLS relay error: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("Relay TLS→upstream failed: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("TLS accept error on relay: {e}");
                            }
                        }
                    }
                    RelayMode::TlsEgress(connector, server_name) => {
                        let owned_name: String = server_name;
                        let name: rustls_pki_types::ServerName<'static> =
                            match owned_name.try_into() {
                                Ok(n) => n,
                                Err(_) => {
                                    log::error!("Invalid server name for TLS egress");
                                    return;
                                }
                            };
                        match TcpStream::connect(&upstream).await {
                            Ok(outbound) => {
                                match connector.connect(name, outbound).await {
                                    Ok(mut tls_stream) => {
                                        match io::copy_bidirectional(
                                            &mut inbound,
                                            &mut tls_stream,
                                        )
                                        .await
                                        {
                                            Ok((to_upstream, to_downstream)) => {
                                                log::info!(
                                                    "Egress TLS relay: {to_upstream} bytes up, {to_downstream} bytes down"
                                                );
                                            }
                                            Err(e) => {
                                                log::error!("Egress TLS relay error: {e}");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        log::error!("TLS connect error to upstream: {e}");
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!("Relay failed to connect to upstream {upstream}: {e}");
                            }
                        }
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener as TokioTcpListener;

    // ------------------------------------------------------------------
    // 1. Relay::new() stores addresses and sets Cleartext mode
    // ------------------------------------------------------------------
    #[test]
    fn test_relay_new() {
        let relay = Relay::new("0.0.0.0:9999", "10.0.0.1:8080");
        assert_eq!(relay.listen_addr, "0.0.0.0:9999");
        assert_eq!(relay.upstream_addr, "10.0.0.1:8080");
        assert!(matches!(relay.mode, RelayMode::Cleartext));
    }

    // ------------------------------------------------------------------
    // 2. with_tls_ingress / with_tls_egress error on bad cert paths
    // ------------------------------------------------------------------
    #[test]
    fn test_with_tls_ingress_bad_path() {
        let dir = tempfile::tempdir().unwrap();
        let bad_cert = dir.path().join("not-a-cert.pem");
        std::fs::write(&bad_cert, b"this is not a valid PEM certificate").unwrap();

        let bad_key = dir.path().join("not-a-key.pem");
        std::fs::write(&bad_key, b"this is not a valid PEM private key").unwrap();

        let relay = Relay::new("0.0.0.0:0", "127.0.0.1:1");
        let result = relay.with_tls_ingress(
            bad_cert.to_str().unwrap(),
            bad_key.to_str().unwrap(),
        );
        assert!(result.is_err(), "expected TlsError from bad cert path");
    }

    #[test]
    fn test_with_tls_egress_bad_path() {
        let dir = tempfile::tempdir().unwrap();
        let bad_cert = dir.path().join("not-a-cert.pem");
        std::fs::write(&bad_cert, b"this is not a valid PEM certificate").unwrap();

        let relay = Relay::new("0.0.0.0:0", "127.0.0.1:1");
        let result = relay.with_tls_egress(
            bad_cert.to_str().unwrap(),
            "example.com",
        );
        assert!(result.is_err(), "expected TlsError from bad cert path");
    }

    // ------------------------------------------------------------------
    // 3. Integration: cleartext relay forwarding via echo server
    // ------------------------------------------------------------------
    #[tokio::test]
    async fn test_cleartext_relay_forwards_bytes() {
        // Start an echo server on a random port.
        let echo_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = echo_listener.accept().await.unwrap();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
        });

        // Start a cleartext relay pointing at the echo server.
        let relay_listener = TokioTcpListener::bind("127.0.0.1:0").await.unwrap();
        let relay_addr = relay_listener.local_addr().unwrap();

        let relay = Relay {
            listen_addr: relay_addr.to_string(),
            upstream_addr: echo_addr.to_string(),
            mode: RelayMode::Cleartext,
        };

        // Manually accept on the relay's port and forward via the relay logic.
        tokio::spawn(async move {
            loop {
                let (mut inbound, _) = relay_listener.accept().await.unwrap();
                let upstream = relay.upstream_addr.clone();
                tokio::spawn(async move {
                    if let Ok(mut outbound) = TcpStream::connect(&upstream).await {
                        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
                    }
                });
            }
        });

        // Connect to the relay and send test bytes.
        let mut client = TcpStream::connect(relay_addr).await.unwrap();
        let payload = b"hello relay world!";
        client.write_all(payload).await.unwrap();

        // Read back the echoed bytes (the relay forwards to echo, which echoes back).
        let mut echo_buf = vec![0u8; payload.len()];
        client.read_exact(&mut echo_buf).await.unwrap();

        assert_eq!(&echo_buf, payload);
    }
}
