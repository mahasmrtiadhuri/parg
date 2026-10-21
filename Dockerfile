FROM rust:1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release --workspace
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --create-home parg && mkdir /keys /public && chown parg:parg /keys /public
COPY --from=build /build/target/release/ledger-service /build/target/release/policy-core /build/target/release/adversarial-worker /usr/local/bin/
USER parg
CMD ["ledger-service"]
