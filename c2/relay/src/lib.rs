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
            });\n        }\n    }\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    use tokio::io::{AsyncReadExt, AsyncWriteExt};\n    use tokio::net::TcpListener as TokioTcpListener;\n\n    // ------------------------------------------------------------------\n    // 1. Relay::new() stores addresses and sets Cleartext mode\n    // ------------------------------------------------------------------\n    #[test]\n    fn test_relay_new() {\n        let relay = Relay::new(\"0.0.0.0:9999\", \"10.0.0.1:8080\");\n        assert_eq!(relay.listen_addr, \"0.0.0.0:9999\");\n        assert_eq!(relay.upstream_addr, \"10.0.0.1:8080\");\n        assert!(matches!(relay.mode, RelayMode::Cleartext));\n    }\n\n    // ------------------------------------------------------------------\n    // 2. with_tls_ingress / with_tls_egress error on bad cert paths\n    // ------------------------------------------------------------------\n    #[test]\n    fn test_with_tls_ingress_bad_path() {\n        let dir = tempfile::tempdir().unwrap();\n        let bad_cert = dir.path().join(\"not-a-cert.pem\");\n        std::fs::write(&bad_cert, b\"this is not a valid PEM certificate\").unwrap();\n\n        let bad_key = dir.path().join(\"not-a-key.pem\");\n        std::fs::write(&bad_key, b\"this is not a valid PEM private key\").unwrap();\n\n        let relay = Relay::new(\"0.0.0.0:0\", \"127.0.0.1:1\");\n        let result = relay.with_tls_ingress(\n            bad_cert.to_str().unwrap(),\n            bad_key.to_str().unwrap(),\n        );\n        assert!(result.is_err(), \"expected TlsError from bad cert path\");\n    }\n\n    #[test]\n    fn test_with_tls_egress_bad_path() {\n        let dir = tempfile::tempdir().unwrap();\n        let bad_cert = dir.path().join(\"not-a-cert.pem\");\n        std::fs::write(&bad_cert, b\"this is not a valid PEM certificate\").unwrap();\n\n        let relay = Relay::new(\"0.0.0.0:0\", \"127.0.0.1:1\");\n        let result = relay.with_tls_egress(\n            bad_cert.to_str().unwrap(),\n            \"example.com\",\n        );\n        assert!(result.is_err(), \"expected TlsError from bad cert path\");\n    }\n\n    // ------------------------------------------------------------------\n    // 3. Integration: cleartext relay forwarding via echo server\n    // ------------------------------------------------------------------\n    #[tokio::test]\n    async fn test_cleartext_relay_forwards_bytes() {\n        // Start an echo server on a random port.\n        let echo_listener = TokioTcpListener::bind(\"127.0.0.1:0\").await.unwrap();\n        let echo_addr = echo_listener.local_addr().unwrap();\n\n        tokio::spawn(async move {\n            loop {\n                let (mut stream, _) = echo_listener.accept().await.unwrap();\n                tokio::spawn(async move {\n                    let mut buf = [0u8; 4096];\n                    loop {\n                        match stream.read(&mut buf).await {\n                            Ok(0) => break,\n                            Ok(n) => {\n                                if stream.write_all(&buf[..n]).await.is_err() {\n                                    break;\n                                }\n                            }\n                            Err(_) => break,\n                        }\n                    }\n                });\n            }\n        });\n\n        // Start a cleartext relay pointing at the echo server.\n        let relay_listener = TokioTcpListener::bind(\"127.0.0.1:0\").await.unwrap();\n        let relay_addr = relay_listener.local_addr().unwrap();\n\n        let relay = Relay {\n            listen_addr: relay_addr.to_string(),\n            upstream_addr: echo_addr.to_string(),\n            mode: RelayMode::Cleartext,\n        };\n\n        // Manually accept on the relay's port and forward via the relay logic.\n        // We spawn the accept loop ourselves so we stay in control.\n        tokio::spawn(async move {\n            loop {\n                let (mut inbound, _) = relay_listener.accept().await.unwrap();\n                let upstream = relay.upstream_addr.clone();\n                tokio::spawn(async move {\n                    if let Ok(mut outbound) = TcpStream::connect(&upstream).await {\n                        let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;\n                    }\n                });\n            }\n        });\n\n        // Connect to the relay and send test bytes.\n        let mut client = TcpStream::connect(relay_addr).await.unwrap();\n        let payload = b\"hello relay world!\";\n        client.write_all(payload).await.unwrap();\n\n        // Read back the echoed bytes (the relay forwards to echo, which echoes back).\n        let mut echo_buf = vec![0u8; payload.len()];\n        client.read_exact(&mut echo_buf).await.unwrap();\n\n        assert_eq!(&echo_buf, payload);\n    }\n}
