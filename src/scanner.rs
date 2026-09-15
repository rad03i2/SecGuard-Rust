use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service_name: String,
    pub banner: Option<String>,
    pub latency_ms: u64,
}

pub struct PortScanner {
    timeout_duration: Duration,
}

impl PortScanner {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout_duration: Duration::from_millis(timeout_ms),
        }
    }

    pub async fn scan_port(&self, addr: SocketAddr) -> PortResult {
        let start = std::time::Instant::now();
        let port = addr.port();
        let service_name = Self::guess_service(port);

        match timeout(self.timeout_duration, TcpStream::connect(&addr)).await {
            Ok(Ok(mut stream)) => {
                let latency = start.elapsed().as_millis() as u64;
                let banner = Self::grab_banner(&mut stream).await;

                PortResult {
                    port,
                    is_open: true,
                    service_name: service_name.to_string(),
                    banner,
                    latency_ms: latency,
                }
            }
            _ => PortResult {
                port,
                is_open: false,
                service_name: service_name.to_string(),
                banner: None,
                latency_ms: 0,
            },
        }
    }

    async fn grab_banner(stream: &mut TcpStream) -> Option<String> {
        let mut buffer = [0u8; 256];
        // Send a generic probe
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
        
        match timeout(Duration::from_millis(500), stream.read(&mut buffer)).await {
            Ok(Ok(n)) if n > 0 => {
                let s = String::from_utf8_lossy(&buffer[..n]);
                let first_line = s.lines().next().unwrap_or("").trim();
                if !first_line.is_empty() {
                    Some(first_line.to_string())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn guess_service(port: u16) -> &'static str {
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            993 => "IMAPS",
            995 => "POP3S",
            1433 => "MSSQL",
            3306 => "MySQL",
            5432 => "PostgreSQL",
            6379 => "Redis",
            8000 => "HTTP-Alt",
            8080 => "HTTP-Proxy",
            8443 => "HTTPS-Alt",
            9000 => "SonarQube/MinIO",
            _ => "Unknown",
        }
    }
}
