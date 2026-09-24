use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult { pub port: u16, pub is_open: bool, pub service_name: String, pub banner: Option<String>, pub latency_ms: u64 }

pub struct PortScanner { timeout_duration: Duration }
impl PortScanner {
    pub fn new(timeout_ms: u64) -> Self { Self { timeout_duration: Duration::from_millis(timeout_ms) } }
    pub async fn scan_port(&self, addr: SocketAddr) -> PortResult {
        let start = Instant::now(); let port = addr.port(); let service = Self::guess_service(port).to_string();
        match timeout(self.timeout_duration, TcpStream::connect(addr)).await {
            Ok(Ok(mut stream)) => PortResult { port, is_open: true, service_name: service, banner: self.grab_banner(port, &mut stream).await, latency_ms: start.elapsed().as_millis() as u64 },
            _ => PortResult { port, is_open: false, service_name: service, banner: None, latency_ms: 0 },
        }
    }
    async fn grab_banner(&self, port: u16, stream: &mut TcpStream) -> Option<String> {
        if matches!(port, 80 | 8000 | 8080) { let _ = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n").await; }
        let mut buf = [0u8; 256];
        match timeout(Duration::from_millis(self.timeout_duration.as_millis().min(500) as u64), stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => sanitize_banner(&buf[..n]), _ => None
        }
    }
    pub fn guess_service(port: u16) -> &'static str { match port { 21=>"FTP",22=>"SSH",23=>"Telnet",25=>"SMTP",53=>"DNS",80=>"HTTP",110=>"POP3",143=>"IMAP",443=>"HTTPS",445=>"SMB",993=>"IMAPS",995=>"POP3S",1433=>"MSSQL",3306=>"MySQL",5432=>"PostgreSQL",6379=>"Redis",8000=>"HTTP-Alt",8080=>"HTTP-Proxy",8443=>"HTTPS-Alt",_=>"Unknown" } }
}
fn sanitize_banner(bytes: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(bytes).replace(['\r','\n','\t'], " ");
    let clean: String = text.chars().filter(|c| !c.is_control()).take(160).collect();
    let clean = clean.trim(); if clean.is_empty() { None } else { Some(clean.to_string()) }
}
#[cfg(test)] mod tests { use super::*; #[test] fn known_services() { assert_eq!(PortScanner::guess_service(22), "SSH"); assert_eq!(PortScanner::guess_service(65000), "Unknown"); } #[test] fn sanitizes_banner() { assert_eq!(sanitize_banner(b"SSH-2.0-test\r\n").unwrap(), "SSH-2.0-test"); } }
