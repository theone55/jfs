# For MCP directories (Glama) that start the server to list its tools. jfs is a thin client of the JFSecure
# desktop app: here, without the app, `jfs mcp` still answers initialize / tools/list, and a tool call reports
# that JFSecure isn't running. Real use: install the app, see README.
FROM rust:1-slim-trixie AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:trixie-slim
COPY --from=build /src/target/release/jfs /usr/local/bin/jfs
ENTRYPOINT ["jfs", "mcp"]
