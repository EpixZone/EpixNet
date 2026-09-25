# Fixed glibc baseline: Ubuntu 22.04, also usable on 24.04-based Zorin 18.
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
COPY install-build-deps.sh /tmp/install-build-deps.sh
RUN bash /tmp/install-build-deps.sh && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup CARGO_HOME=/usr/local/cargo
ENV PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o /tmp/rustup.sh \
    && sh /tmp/rustup.sh -y --profile minimal --default-toolchain stable \
    && rm /tmp/rustup.sh
WORKDIR /src
CMD ["bash", "packaging/linux/build-linux.sh"]
