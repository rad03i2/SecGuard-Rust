# SecGuard-Rust

A focused Rust CLI for **authorized** TCP exposure checks and real TLS handshake inspection. SecGuard favors clear, reproducible results over vulnerability claims it cannot prove.

> Use only on hosts you own or have explicit permission to assess.

## English

### Overview & why it exists
SecGuard answers two practical questions during defensive reviews: which requested TCP ports accept connections, and can a selected endpoint complete a certificate-validated TLS handshake? It is useful for local labs, server inventories, deployment checks, and defensive troubleshooting.

### Features
- Concurrent asynchronous TCP connect scanning with a bounded concurrency setting.
- Port lists and ranges such as `22,80,443,8000-8010`, with validation and deduplication.
- Conservative service-name hints for common ports.
- Limited banner reads; an HTTP `HEAD` probe is sent only to known plain-HTTP ports.
- Optional **real** TLS handshake using rustls and Mozilla root certificates; reports negotiated protocol, cipher suite, certificate-chain length, and handshake errors.
- Human-readable terminal output or structured JSON.
- DNS resolution with the resolved address included in reports.
- Timeouts and safe CLI bounds; no exploit, credential, or authentication-bypass behavior.

### Preview
```text
SecGuard v1.1.0 — authorized targets only
Target: 127.0.0.1 (127.0.0.1) | ports: 3 | concurrency: 100
PORT     SERVICE          LATENCY      BANNER
22       SSH              1ms          SSH-2.0-OpenSSH...
```
Output depends on the target; the example above is illustrative, not a benchmark or claim about a real host.

### Requirements & installation
Rust stable (edition 2021) is required.

```bash
git clone https://github.com/rad03i2/SecGuard-Rust.git
cd SecGuard-Rust
cargo build --release
./target/release/secguard --help
```

Windows PowerShell users can run `target\release\secguard.exe`.

### Usage
```bash
# Local machine, selected ports
secguard --target 127.0.0.1 --ports 22,80,443

# Range + JSON
secguard --target localhost --ports 8000-8010 --json

# Verify TLS on a specific authorized endpoint
secguard --target example.com --ports 443 --tls-port 443

# Tune connection timeout/concurrency
secguard --target 192.0.2.10 --ports 1-1024 --concurrency 64 --timeout-ms 1200
```
`--tls-port` is explicit because an open port number alone does not prove that TLS is in use.

### Configuration
SecGuard uses CLI flags only; no `.env`, API key, account, or telemetry is required. Run `secguard --help` for the authoritative options.

### Project structure
```text
src/main.rs       CLI, validation, resolution, orchestration
src/scanner.rs    TCP connect scanner and conservative banner reader
src/tls.rs        certificate-validated TLS handshake inspector
src/reporter.rs   console and JSON reports
.github/workflows/ci.yml   formatting, lint, test and build checks
SECURITY.md       security/use policy
CONTRIBUTING.md   contribution guide
```

### Testing
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```
CI runs these checks on Ubuntu, Windows, and macOS. Unit tests cover port parsing, validation, service mapping, and banner sanitization without scanning third-party systems.

### Security & privacy
Scanning can trigger monitoring systems and may violate policy or law without authorization. SecGuard does not upload scan data, use analytics, exploit services, brute-force credentials, or bypass authentication. JSON output and banners can still contain infrastructure details; store them appropriately. See [SECURITY.md](SECURITY.md).

### Limitations
This is not a vulnerability scanner, exploit framework, UDP scanner, stealth scanner, CIDR sweeper, or compliance engine. A successful TCP connection does not prove a service is secure. Service names are port-based hints. Banner data can be absent or misleading. TLS inspection validates the live handshake and trust chain but does not currently decode certificate expiry/SAN fields or grade cryptographic policy. DNS currently uses the first resolved address.

### Optional roadmap
- Certificate metadata parsing and explicit expiry reporting.
- IPv4/IPv6 address-selection controls.
- SARIF export for defensive CI workflows.

### Contributing & license
See [CONTRIBUTING.md](CONTRIBUTING.md). Licensed under the [MIT License](LICENSE).

### Author
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**

---

## العربية

### نظرة عامة ولماذا يوجد المشروع
SecGuard أداة سطر أوامر مكتوبة بلغة Rust لفحص منافذ TCP على الأنظمة التي تملكها أو لديك تصريح صريح لفحصها، مع إمكانية إجراء اتصال TLS حقيقي والتحقق من سلسلة الثقة. صُممت للأعمال الدفاعية مثل فحص الخادم المحلي، جرد الخدمات، والتحقق بعد النشر، من دون ادعاء اكتشاف ثغرات لم يتم إثباتها.

### الميزات
- فحص TCP غير متزامن ومتوازي مع حد واضح للتزامن.
- قبول قوائم ومديات مثل `22,80,443,8000-8010` مع التحقق وإزالة التكرار.
- تخمين محافظ لاسم الخدمة اعتمادًا على رقم المنفذ.
- قراءة محدودة للـbanner؛ ولا يُرسل طلب HTTP إلا إلى منافذ HTTP المعروفة.
- فحص TLS **فعلي** واختياري باستخدام rustls وجذور Mozilla، مع عرض البروتوكول وCipher Suite وطول سلسلة الشهادة وأخطاء الاتصال.
- مخرجات طرفية واضحة أو JSON.
- إظهار عنوان IP الذي تم حله من اسم المضيف.
- لا توجد وظائف استغلال أو تخمين كلمات مرور أو تجاوز مصادقة.

### التثبيت والتشغيل
يتطلب Rust stable.
```bash
git clone https://github.com/rad03i2/SecGuard-Rust.git
cd SecGuard-Rust
cargo build --release
./target/release/secguard --target 127.0.0.1 --ports 22,80,443
```
لفحص TLS على منفذ مصرح به:
```bash
./target/release/secguard --target example.com --ports 443 --tls-port 443
```
ولعرض جميع الخيارات استخدم `secguard --help`.

### الإعداد
لا يحتاج المشروع إلى `.env` أو مفاتيح API أو حساب خارجي. جميع الإعدادات عبر خيارات CLI، ومنها الهدف والمنافذ والتزامن والمهلة ومنفذ TLS وصيغة JSON.

### بنية المشروع
`main.rs` يدير CLI والتحقق، و`scanner.rs` ينفذ فحص TCP، و`tls.rs` يجري TLS handshake حقيقيًا، و`reporter.rs` يبني التقرير. توجد اختبارات وCI ووثائق أمان ومساهمة ضمن المستودع.

### الاختبارات
```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```
تم إعداد GitHub Actions لتشغيل هذه الفحوص على Linux وWindows وmacOS من دون فحص أهداف عامة أثناء الاختبارات.

### الأمان والخصوصية
استخدم الأداة فقط على أنظمة تملكها أو لديك تصريح واضح لفحصها. لا يرسل SecGuard نتائجك إلى خدمة خارجية، ولا يحتوي telemetry، ولا ينفذ استغلالًا أو brute force. قد تحتوي تقارير JSON والـbanners على معلومات بنية تحتية حساسة، لذا تعامل معها بعناية. راجع [SECURITY.md](SECURITY.md).

### القيود
SecGuard ليس ماسح ثغرات شاملًا ولا إطار استغلال ولا ماسح UDP/CIDR ولا أداة stealth أو compliance. أسماء الخدمات مجرد تخمين مبني على المنافذ، وقد تكون الـbanners غائبة أو مضللة. فحص TLS يتحقق من الاتصال وسلسلة الثقة لكنه لا يحلل حاليًا تاريخ انتهاء الشهادة أو SAN ولا يمنح تقييمًا تشفيريًا. عند تعدد نتائج DNS يستخدم أول عنوان حاليًا.

### تطوير اختياري مستقبلًا
يمكن إضافة تحليل بيانات الشهادة، والتحكم باختيار IPv4/IPv6، وتصدير SARIF من دون تغيير الهدف الأساسي للمشروع.

### المساهمة والترخيص
راجع [CONTRIBUTING.md](CONTRIBUTING.md). المشروع مرخص وفق [MIT](LICENSE).

### المؤلف
**Radwan Abdulhadi Ahmed**  
**رضوان عبدالهادي أحمد**  
GitHub: **@rad03i2**
