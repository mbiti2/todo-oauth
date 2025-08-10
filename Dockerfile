# syntax=docker/dockerfile:1
FROM rust:latest as builder
WORKDIR /app
COPY . .
RUN cargo build --release

#FROM debian:buster-slim
FROM debian:bookworm-slim
WORKDIR /app
# Install OpenSSL 3 runtime library
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/todo-service /app/todo-service
COPY templates ./templates
COPY todos.json .
EXPOSE 3000
CMD ["/app/todo-service"]