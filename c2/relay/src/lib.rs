use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct Relay {
    pub listen_addr: String,
}

impl Relay {
    pub fn new(listen_addr: &str) -> Self {
        Self {
            listen_addr: listen_addr.to_string(),
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(&self.listen_addr).await?;
        println!("Relay listening on {}", self.listen_addr);

        loop {
            let (mut socket, _) = listener.accept().await?;
            tokio::spawn(async move {
                // Simple transparent forwarding logic 
                // For now: just read from one and write to another
                // Real relay will handle upstream C2 mapping
                let mut buffer = [0u8; 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) => break,
                        Ok(n) => {
                            socket.write_all(&buffer[..n]).await.unwrap();
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    }
}
