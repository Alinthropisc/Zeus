# Builder stage
FROM rust:1.82-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev protobuf-compiler && rm -rf /var/lib/apt/lists/*
COPY . .
RUN cargo build --release --bin zeus

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
WORKDIR /zeus
COPY --from=builder /app/target/release/zeus /usr/local/bin/zeus
ENTRYPOINT ["zeus"]
