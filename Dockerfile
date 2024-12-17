FROM messense/rust-musl-cross:x86_64-musl AS builder
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM scratch
EXPOSE 3030
EXPOSE 3031
COPY --from=builder /app/credential /credential
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/signurl /signurl
CMD ["/signurl"]
