# garrett, the Sentinel agent, for container hosts. Build from the repository root:
#   docker build -f deploy/Dockerfile -t garrett .
FROM rust:1-slim AS build
COPY rust /src/rust
RUN cd /src/rust && cargo build --release --locked

FROM debian:stable-slim
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 nftables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/rust/target/release/garrett /opt/sentinel/garrett
COPY deploy/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
