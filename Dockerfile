# Support setting various labels on the final image
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

FROM rust:bullseye AS rust-builder

ADD ./ballots /ballots
RUN cd /ballots && cargo build --release

# Build Geth in a stock Go builder container
FROM golang:1.24-bullseye AS builder

RUN apt-get update && apt-get install -y build-essential libc6-dev git

# Get dependencies - will also be cached if we won't change go.mod/go.sum
COPY go.mod /go-ethereum/
COPY go.sum /go-ethereum/
RUN cd /go-ethereum && go mod download

COPY --from=rust-builder /ballots/target/release/libballots.so /usr/lib/

ADD . /go-ethereum
RUN cd /go-ethereum && go run build/ci.go install ./cmd/geth

# Pull Geth into a second stage deploy alpine container
FROM debian:latest

RUN apt-get update && apt-get install -y ca-certificates
COPY --from=builder /go-ethereum/build/bin/geth /usr/local/bin/
COPY --from=rust-builder /ballots/target/release/libballots.so /usr/lib/

EXPOSE 8545 8546 30303 30303/udp
ENTRYPOINT ["geth"]

# Add some metadata labels to help programmatic image consumption
ARG COMMIT=""
ARG VERSION=""
ARG BUILDNUM=""

LABEL commit="$COMMIT" version="$VERSION" buildnum="$BUILDNUM"
