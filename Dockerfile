# syntax=docker/dockerfile:1.7

FROM rust:1.93-bookworm AS builder
WORKDIR /src

RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y --no-install-recommends musl-tools pkg-config && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine:3.21 AS runtime
WORKDIR /app
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/packet_handler /usr/local/bin/packet_handler
ENTRYPOINT ["/usr/local/bin/packet_handler"]

# Exporter target: run with dist volume mounted and copy binary out.
FROM alpine:3.21 AS exporter
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/packet_handler /packet_handler
ENTRYPOINT ["/bin/sh", "-lc"]
CMD ["cp /packet_handler /dist/packet_handler && chmod +x /dist/packet_handler"]
