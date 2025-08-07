# Multi-stage build for optimized image size
FROM rust:1.75-slim AS rust-builder

# Install dependencies for Rust build
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Install security scanner
RUN cargo install cargo-audit

# Set working directory
WORKDIR /app

# Copy Cargo files
COPY Cargo.toml Cargo.lock ./
COPY rustcore/Cargo.toml ./rustcore/
COPY exploit_detector/Cargo.toml ./exploit_detector/

# Create dummy source files for dependencies
RUN mkdir -p src rustcore/src exploit_detector/src
RUN echo "fn main() {}" > src/main.rs
RUN echo "fn main() {}" > rustcore/src/lib.rs
RUN echo "fn main() {}" > exploit_detector/src/main.rs

# Build Rust dependencies
RUN cargo build --release

# Copy actual source code
COPY src ./src
COPY rustcore/src ./rustcore/src
COPY exploit_detector/src ./exploit_detector/src

# Run security audit
RUN cargo audit

# Build the Rust application
RUN cargo build --release

# Python extension builder stage
FROM python:3.11-slim AS python-builder

# Install Rust and dependencies for PyO3
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install maturin for building Python extensions
RUN pip install maturin==1.3.0

# Set working directory
WORKDIR /app

# Copy Cargo files and pyproject.toml for Python extension
COPY Cargo.toml Cargo.lock ./
COPY rustcore/Cargo.toml ./rustcore/
COPY rustcore/requirements.txt ./
RUN pip install -r requirements.txt

# Create dummy source files for dependencies
RUN mkdir -p rustcore/src
RUN echo "fn main() {}" > rustcore/src/lib.rs

# Build Python extension dependencies
RUN maturin build --release --manylinux 2014 --out dist

# Copy actual source code
COPY rustcore/src ./rustcore/src

# Build the Python extension
RUN maturin build --release --manylinux 2014 --out dist

# Runtime image
FROM python:3.11-slim AS runtime

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 security

# Set working directory
WORKDIR /app

# Copy binary from rust-builder
COPY --from=rust-builder /app/target/release/exploit_detector /usr/local/bin/

# Install Python extension
COPY --from=python-builder /app/dist/*.whl ./
RUN pip install *.whl

# Copy configuration files
COPY src/.env.example .env

# Create directories
RUN mkdir -p /var/lib/security-monitoring /var/log/security-monitoring /app/config

# Set permissions
RUN chown -R security:security /app /var/lib/security-monitoring /var/log/security-monitoring

# Switch to non-root user
USER security

# Expose ports
EXPOSE 8000 8001 9090

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Entry point
ENTRYPOINT ["/usr/local/bin/exploit_detector"]