mod reporter;
mod scanner;
mod tls;

use clap::Parser;
use colored::*;
use futures::stream::{self, StreamExt};
use reporter::{FullAuditReport, Reporter};
use scanner::PortScanner;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tls::TlsInspector;

#[derive(Parser, Debug)]
#[command(author = "Radwan Abdulhadi Ahmed (@rad03i2)", version, about = "Async TCP port scanner and TLS inspector for authorized auditing")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    target: String,
    #[arg(short, long, default_value = "1-1024")]
    ports: String,
    #[arg(short, long, default_value_t = 100, value_parser = clap::value_parser!(usize).range(1..=4096))]
    concurrency: usize,
    #[arg(short = 'w', long, default_value_t = 800, value_parser = clap::value_parser!(u64).range(50..=60000))]
    timeout_ms: u64,
    #[arg(long, help = "Perform a verified TLS handshake on this port")]
    tls_port: Option<u16>,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => { eprintln!("Invalid --ports value: {e}"); std::process::exit(2); }
    };
    let target_ip = match resolve_target(&args.target) {
        Ok(ip) => ip,
        Err(e) => { eprintln!("{e}"); std::process::exit(2); }
    };
    if !args.json {
        println!("{}", "SecGuard v1.1.0 — authorized targets only".bold().cyan());
        println!("Target: {} ({}) | ports: {} | concurrency: {}", args.target.yellow(), target_ip, ports.len(), args.concurrency);
    }

    let scanner = Arc::new(PortScanner::new(args.timeout_ms));
    let results = stream::iter(ports)
        .map(|port| { let s = Arc::clone(&scanner); let addr = SocketAddr::new(target_ip, port); async move { s.scan_port(addr).await } })
        .buffer_unordered(args.concurrency)
        .collect::<Vec<_>>().await;
    let mut open_ports: Vec<_> = results.into_iter().filter(|p| p.is_open).collect();
    open_ports.sort_by_key(|p| p.port);

    let tls_audit = match args.tls_port {
        Some(port) => Some(TlsInspector::audit_host(&args.target, port, args.timeout_ms).await),
        None => None,
    };
    let report = FullAuditReport { target: args.target, resolved_ip: target_ip.to_string(), timestamp: chrono::Utc::now().to_rfc3339(), open_ports, tls_audit };
    if args.json { println!("{}", Reporter::to_json(&report)); } else { Reporter::print_console(&report); }
}

fn resolve_target(target: &str) -> Result<IpAddr, String> {
    format!("{target}:0").to_socket_addrs().map_err(|e| format!("DNS resolution failed: {e}"))?
        .next().map(|a| a.ip()).ok_or_else(|| "target resolved to no addresses".to_string())
}

fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for token in input.split(',') {
        let token = token.trim();
        if token.is_empty() { return Err("empty port token".into()); }
        if let Some((a, b)) = token.split_once('-') {
            let start: u16 = a.trim().parse().map_err(|_| format!("bad port: {a}"))?;
            let end: u16 = b.trim().parse().map_err(|_| format!("bad port: {b}"))?;
            if start == 0 || end == 0 || start > end { return Err(format!("invalid range: {token}")); }
            ports.extend(start..=end);
        } else {
            let port: u16 = token.parse().map_err(|_| format!("bad port: {token}"))?;
            if port == 0 { return Err("port 0 is not supported".into()); }
            ports.push(port);
        }
    }
    ports.sort_unstable(); ports.dedup();
    if ports.len() > 65_535 { return Err("too many ports".into()); }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn parses_lists_ranges_and_deduplicates() { assert_eq!(parse_ports("80,443,8000-8002,80").unwrap(), vec![80,443,8000,8001,8002]); }
    #[test] fn rejects_bad_ports() { for value in ["0", "443-80", "abc", "80,,443"] { assert!(parse_ports(value).is_err()); } }
}
