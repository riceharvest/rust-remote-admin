use tokio::net::{TcpListener, TcpStream};
use tokio::io;

pub struct Relay {
    pub listen_addr: String,
    pub upstream_addr: String,
}

impl Relay {
    #[must_use]
    pub fn new(listen_addr: &str, upstream_addr: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
            upstream_addr: upstream_addr.to_string(),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        log::info!("Relay listening on {listen_addr}", listen_addr = self.listen_addr);

        loop {
            let (mut inbound, _) = listener.accept().await?;
            let upstream = self.upstream_addr.clone();

            tokio::spawn(async move {
                match TcpStream::connect(&upstream).await {
                    Ok(mut outbound) => {
                        match io::copy_bidirectional(&mut inbound, &mut outbound).await {
                            Ok((to_upstream, to_downstream)) => {
                                log::info!("Relay session closed: {to_upstream} bytes up, {to_downstream} bytes down");
                            }
                            Err(e) => {
                                log::error!("Relay error: {e}");
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Relay failed to connect to upstream {upstream}: {e}");
                    }
                }
            });
        }
    }
}
