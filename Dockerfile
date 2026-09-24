FROM rust:1.85-slim-bookworm AS builder
WORKDIR /usr/src/secguard
COPY . .
RUN cargo build --release --locked || cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --uid 10001 secguard
COPY --from=builder /usr/src/secguard/target/release/secguard /usr/local/bin/secguard
USER secguard
ENTRYPOINT ["secguard"]
CMD ["--help"]
