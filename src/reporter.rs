use crate::scanner::PortResult;
use crate::tls::TlsAuditReport;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FullAuditReport { pub target: String, pub resolved_ip: String, pub timestamp: String, pub open_ports: Vec<PortResult>, pub tls_audit: Option<TlsAuditReport> }
pub struct Reporter;
impl Reporter {
    pub fn print_console(report: &FullAuditReport) {
        println!("\n{}", "SecGuard Network Audit".bold().green());
        println!("Target: {} ({})", report.target.bold().yellow(), report.resolved_ip);
        println!("Timestamp: {} | Open ports: {}\n", report.timestamp, report.open_ports.len());
        println!("{:<8} {:<16} {:<12} {}", "PORT", "SERVICE", "LATENCY", "BANNER");
        for p in &report.open_ports { println!("{:<8} {:<16} {:<12} {}", p.port.to_string().green(), p.service_name.yellow(), format!("{}ms", p.latency_ms), p.banner.as_deref().unwrap_or("-")); }
        if let Some(tls) = &report.tls_audit {
            println!("\n{}", "TLS handshake inspection".bold().blue());
            println!("Port: {} | Handshake verified: {}", tls.port, if tls.handshake_ok { "yes".green() } else { "no".red() });
            println!("Protocol: {}", tls.protocol_version.as_deref().unwrap_or("-"));
            println!("Cipher: {}", tls.cipher_suite.as_deref().unwrap_or("-"));
            println!("Certificate chain entries: {}", tls.certificate_chain_length);
            if let Some(error) = &tls.error { println!("Error: {}", error.red()); }
        }
    }
    pub fn to_json(report: &FullAuditReport) -> String { serde_json::to_string_pretty(report).expect("serializing report should not fail") }
}
