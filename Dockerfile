FROM rust:1.76-slim as builder
WORKDIR /usr/src/secguard
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/src/secguard/target/release/secguard /usr/local/bin/secguard
ENTRYPOINT ["secguard"]
CMD ["--help"]
