FROM rust as builder

WORKDIR trin

RUN apt-get update && apt-get install clang -y

COPY ./src ./src 
COPY ./trin-core ./trin-core 
COPY ./trin-history ./trin-history 
COPY ./trin-state ./trin-state 
COPY ./ethportal-peertest ./ethportal-peertest 
COPY ./Cargo.lock ./Cargo.lock 
COPY ./Cargo.toml ./Cargo.toml 

#RUN cargo build --release --bin trin
RUN rustup component add rustfmt
RUN cargo build --bin trin

#FROM rust as runtime
#WORKDIR trin
#COPY --from=builder /trin/target/debug/trin /usr/local/bin

#ENTRYPOINT ["./usr/local/bin/trin"]
ENV RUST_LOG=debug

# good
ENTRYPOINT ["./target/debug/trin"]
