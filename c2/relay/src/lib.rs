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
