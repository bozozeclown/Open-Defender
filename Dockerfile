# Stage 1: Build
FROM rust:1.74-slim as builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
COPY exploit_detector/ exploit_detector/
COPY rustcore/ rustcore/
# Cache deps
RUN cargo fetch
COPY . .
RUN cargo build --release --locked

# Stage 2: Runtime
FROM gcr.io/distroless/cc-debian12
WORKDIR /app
COPY --from=builder /app/target/release/security-monitoring /usr/local/bin/
COPY config/ /app/config/
USER nonroot:nonroot
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=3 \
    CMD wget -qO- http://localhost:8000/health || exit 1
ENTRYPOINT ["security-monitoring"]
