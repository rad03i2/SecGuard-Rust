<div align="center">

# 🛡️ SecGuard-Rust
### Blazing-Fast Asynchronous Network Vulnerability Scanner, SSL/TLS Inspector & Security Auditor
#### أداة أمن سيبراني فائقة السرعة لفحص منافذ الشبكات، تدقيق شهادات التشفير، ورصد الثغرات

[![Rust](https://img.shields.io/badge/Rust-2021%20Edition-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://rust-lang.org)
[![Tokio Async](https://img.shields.io/badge/Async-Tokio%20Runtime-blue?style=for-the-badge)](https://tokio.rs)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

<br/>

[English Documentation](#-english-overview) • [التوثيق بالعربية](#-نظرة-عامة-باللغة-العربية) • [Quick Start](#-quick-start) • [Architecture](#-architecture) • [Cybersecurity Services](#-commercial-cybersecurity--penetration-testing-consulting)

</div>

---

## 🌟 Highlights

**SecGuard-Rust** is a systems-level network audit tool engineered in Rust for extreme concurrency and safety. Powered by the **Tokio async runtime**, it scans thousands of network ports per second, grabs service banners, audits SSL/TLS cipher suites, and generates structured JSON security assessments.

---

## 🚀 Key Features

- ⚡ **Asynchronous Concurrency**: Built with Tokio green threads; scans 1,000+ ports in under 3 seconds.
- 🔍 **Service Banner Grabbing**: Identifies exposed web servers, SSH daemons, databases, and version strings.
- 🔐 **SSL/TLS Security Audit**: Inspects certificate expiration, cipher suite strengths, and encryption protocol versions (TLS 1.2 vs 1.3).
- 📊 **Dual Output Modes**: Beautiful colored terminal tables or machine-readable JSON for CI/CD DevSecOps pipelines.
- 🛡️ **Memory Safe & Zero-Cost Abstractions**: 100% safe Rust without buffer overflow risks.

---

## 🏛️ Architecture

```text
                     [ Target Host / CIDR Range ]
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │   Tokio Task Dispatcher  │  ◄── 100+ Concurrent Green Threads
                     └────────────┬─────────────┘
                                  │
         ┌────────────────────────┼────────────────────────┐
         ▼                        ▼                        ▼
 ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
 │ Port Connect  │        │ Banner Grab   │        │ TLS Inspector │
 └───────┬───────┘        └───────┬───────┘        └───────┬───────┘
         │                        │                        │
         └────────────────────────┼────────────────────────┘
                                  │
                                  ▼
                     ┌──────────────────────────┐
                     │  Audit Reporter & JSON   │
                     └──────────────────────────┘
```

---

## ⚡ Quick Start

### 1. Build from Source
```bash
git clone https://github.com/rad03i2/SecGuard-Rust.git
cd SecGuard-Rust

# Build release binary
cargo build --release

# Run scanner
./target/release/secguard --target 127.0.0.1 --ports 1-1024
```

### 2. Common Scan Examples
```bash
# High-concurrency scan on custom ports
./secguard --target scanme.nmap.org --ports 20-443 --concurrency 250

# Output machine-readable JSON for automated DevSecOps pipelines
./secguard --target example.com --ports 80,443,8080 --json
```

---

## 🇸🇦 نظرة عامة باللغة العربية

### ما هي أداة SecGuard-Rust؟
**SecGuard-Rust** هي أداة أمن سيبراني متقدمة ومكتوبة بلغة Rust للتدقيق الأمني على الشبكات والخوادم. توظف قدرات المعالجة غير المتزامنة (Asynchronous Concurrency) لفحص آلاف المنافذ واكتشاف الثغرات في أجزاء من الثانية بأعلى معايير الأمان البرمجي.

### أهم القدرات:
1. **فحص المنافذ فائق السرعة**: فحص متزامن لمئات المنافذ دون استهلاك الذاكرة أو التسبب في تجميد النظام.
2. **سحب البصمات الأمنية (Banner Grabbing)**: معرفة إصدارات البرامج والخدمات المفتوحة (SSH, HTTP, Databases) لتحديد الثغرات المحتملة.
3. **فحص شهادات التشفير (SSL/TLS Audit)**: التحقق من صلاحية شهادات الحماية وقوة خوارزميات التشفير المستخدمة.
4. **تكامل مع أنظمة الـ CI/CD**: إمكانية تصدير النتائج بصيغة JSON لربطها في خطوط الإنتاج والتحقق الأمني الدوري.

---

## 💼 Commercial Cybersecurity & Penetration Testing Consulting
### استشارات الأمن السيبراني وتطوير الأدوات المخصصة

Looking for customized vulnerability scanning tools, automated DevSecOps pipelines, or infrastructure security audits?
هل تبحث عن بناء أدوات فحص أمني مخصصة، أو تأمين بنيتك التحتية السحابية؟

- 📩 **Contact**: Reach out via GitHub [@rad03i2](https://github.com/rad03i2)
- 🤝 **Consulting & Contract Engineering**: Open for cybersecurity engineering and secure systems development in Rust.

---

## 📄 License
Licensed under the [MIT License](LICENSE). Developed by [rad03i2](https://github.com/rad03i2).
