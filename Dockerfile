# IronScope development Dockerfile.
# For the release image, see docker/Dockerfile.release.
#
# Build: docker build -t ironscope:dev .
# Run:   docker run --privileged --pid=host ironscope:dev --help
#
# The builder uses Rust 1.96.0 plus nightly rust-src and bpf-linker because
# aya-build compiles the embedded eBPF object during the userspace build.

FROM rust:1.96-bookworm AS builder
WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      clang \
      libclang-dev \
      libbpf-dev \
      llvm \
      pkg-config \
      zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install nightly --profile minimal --component rust-src && \
    cargo +nightly install bpf-linker --locked

COPY . .
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/ironscope /usr/bin/ironscope
COPY --from=builder /build/tools/python-contracts /usr/share/ironscope/python-contracts
COPY --from=builder /build/tools/rules/framework_rules.yaml /usr/share/ironscope/rules/framework_rules.yaml
COPY --from=builder /build/examples/policies /usr/share/ironscope/examples/policies
ENTRYPOINT ["/usr/bin/ironscope"]
