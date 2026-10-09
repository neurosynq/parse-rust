# The parse-rust demo image, built from this checkout. See compose.yaml: this is a demo, not a
# deployment artifact, and nothing here is published to a registry.
#
# Both base images are pinned by digest, so the demo builds the same thing tomorrow as today.

FROM rust:1.89-slim-bookworm@sha256:d7fc7de78bb8c1469933aeecbf801314d30d7d6e9f0578bba4cfa285bfa37fe6 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p parse-rust-cli

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
# curl is here for the healthcheck and nothing else.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/parse-rust /usr/local/bin/parse-rust
EXPOSE 27800
ENTRYPOINT ["/usr/local/bin/parse-rust"]
