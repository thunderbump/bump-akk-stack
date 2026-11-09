ARG BASE
FROM ${BASE}
USER root
ARG RUST_VERSION
ENV PATH=/opt/eqemu-perl/bin:/root/.cargo/bin:$PATH
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates build-essential ninja-build pkg-config libssl-dev libboost-all-dev default-libmysqlclient-dev zlib1g-dev libsodium-dev libluajit-5.1-dev && rm -rf /var/lib/apt/lists/*
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup.sh && sh /tmp/rustup.sh -y --profile minimal --default-toolchain "${RUST_VERSION}" && rm /tmp/rustup.sh
