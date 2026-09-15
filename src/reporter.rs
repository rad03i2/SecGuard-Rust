use crate::scanner::PortResult;
use crate::tls::TlsAuditReport;
use colored::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct FullAuditReport {
    pub target: String,
    pub timestamp: String,
    pub open_ports: Vec<PortResult>,
    pub tls_audit: Option<TlsAuditReport>,
}

pub struct Reporter;

impl Reporter {
    pub fn print_console(report: &FullAuditReport) {
        println!("{}", "\n=======================================================".cyan());
        println!("{}", "       🛡️  SecGuard Security Audit Report".bold().green());
        println!("{}", "=======================================================".cyan());
        println!("Target:        {}", report.target.bold().yellow());
        println!("Timestamp:     {}", report.timestamp);
        println!("Open Ports:    {}\n", report.open_ports.len().to_string().bold().green());

        println!("{:<8} {:<15} {:<12} {:<30}", "PORT", "SERVICE", "LATENCY", "BANNER");
        println!("{}", "-------------------------------------------------------".dimmed());

        for p in &report.open_ports {
            let banner = p.banner.as_deref().unwrap_or("-");
            println!(
                "{:<8} {:<15} {:<12} {:<30}",
                p.port.to_string().green(),
                p.service_name.yellow(),
                format!("{}ms", p.latency_ms).dimmed(),
                banner.dimmed()
            );
        }

        if let Some(tls) = &report.tls_audit {
            println!("{}", "\n--- SSL/TLS Security Posture ---".bold().blue());
            println!("Protocol:      {}", tls.protocol_version.green());
            println!("Cipher Suite:  {}", tls.cipher_suite.dimmed());
            println!("Valid Cert:    {}", if tls.certificate_valid { "YES".green() } else { "NO".red() });
            println!("Expires In:    {} days", tls.days_until_expiration);
        }
        println!("{}", "\n[Audit Completed Successfully]".bold().cyan());
    }

    pub fn to_json(report: &FullAuditReport) -> String {
        serde_json::to_string_pretty(report).unwrap_or_default()
    }
}
