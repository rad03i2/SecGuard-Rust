use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsAuditReport {
    pub host: String,
    pub port: u16,
    pub handshake_ok: bool,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub certificate_chain_length: usize,
    pub error: Option<String>,
}

pub struct TlsInspector;

impl TlsInspector {
    pub async fn audit_host(host: &str, port: u16, timeout_ms: u64) -> TlsAuditReport {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let server_name = match ServerName::try_from(host.to_owned()) {
            Ok(name) => name,
            Err(_) => return Self::failure(host, port, "target is not a valid TLS server name"),
        };
        let tcp = match timeout(Duration::from_millis(timeout_ms), TcpStream::connect((host, port))).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => return Self::failure(host, port, &format!("TCP connection failed: {e}")),
            Err(_) => return Self::failure(host, port, "TCP connection timed out"),
        };
        match timeout(Duration::from_millis(timeout_ms), connector.connect(server_name, tcp)).await {
            Ok(Ok(stream)) => {
                let (_, session) = stream.get_ref();
                TlsAuditReport {
                    host: host.to_string(), port, handshake_ok: true,
                    protocol_version: session.protocol_version().map(|v| format!("{v:?}")),
                    cipher_suite: session.negotiated_cipher_suite().map(|c| format!("{:?}", c.suite())),
                    certificate_chain_length: session.peer_certificates().map_or(0, |c| c.len()),
                    error: None,
                }
            }
            Ok(Err(e)) => Self::failure(host, port, &format!("TLS handshake/certificate validation failed: {e}")),
            Err(_) => Self::failure(host, port, "TLS handshake timed out"),
        }
    }

    fn failure(host: &str, port: u16, error: &str) -> TlsAuditReport {
        TlsAuditReport { host: host.to_string(), port, handshake_ok: false, protocol_version: None,
            cipher_suite: None, certificate_chain_length: 0, error: Some(error.to_string()) }
    }
}
