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
#[command(author = "rad03i2", version = "1.0.0", about = "Blazing-fast async network vulnerability scanner and TLS inspector")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1")]
    target: String,

    #[arg(short, long, default_value = "1-1024")]
    ports: String,

    #[arg(short, long, default_value_t = 100)]
    concurrency: usize,

    #[arg(short, long, default_value_t = 800)]
    timeout_ms: u64,

    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if !args.json {
        println!("{}", "⚡ SecGuard Network Scanner v1.0.0 (Rust Tokio)".bold().cyan());
        println!("Scanning target: {} | Concurrency: {}", args.target.yellow(), args.concurrency);
    }

    // Resolve target IP
    let target_ip: IpAddr = match format!("{}:80", args.target).to_socket_addrs() {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr.ip(),
            None => {
                eprintln!("Failed to resolve target: {}", args.target);
                return;
            }
        },
        Err(e) => {
            eprintln!("DNS resolution error: {}", e);
            return;
        }
    };

    let ports = parse_ports(&args.ports);
    let scanner = Arc::new(PortScanner::new(args.timeout_ms));

    let scan_results: Vec<_> = stream::iter(ports)
        .map(|port| {
            let s = Arc::clone(&scanner);
            let addr = SocketAddr::new(target_ip, port);
            tokio::spawn(async move { s.scan_port(addr).await })
        })
        .buffer_unordered(args.concurrency)
        .collect::<Vec<_>>()
        .await;

    let mut open_ports = Vec::new();
    for res in scan_results {
        if let Ok(port_res) = res {
            if port_res.is_open {
                open_ports.push(port_res);
            }
        }
    }
    open_ports.sort_by_key(|p| p.port);

    // TLS Inspection if port 443 is in range
    let tls_audit = Some(TlsInspector::audit_host(&args.target, 443));

    let report = FullAuditReport {
        target: args.target.clone(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        open_ports,
        tls_audit,
    };

    if args.json {
        println!("{}", Reporter::to_json(&report));
    } else {
        Reporter::print_console(&report);
    }
}

fn parse_ports(port_arg: &str) -> Vec<u16> {
    if let Some((start, end)) = port_arg.split_once('-') {
        let s: u16 = start.trim().parse().unwrap_or(1);
        let e: u16 = end.trim().parse().unwrap_or(1024);
        (s..=e).collect()
    } else {
        port_arg
            .split(',')
            .filter_map(|p| p.trim().parse::<u16>().ok())
            .collect()
    }
}
