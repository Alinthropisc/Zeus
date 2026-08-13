default: check

build:
    cargo build --release

dev:
    cargo build

test:
    cargo test --workspace --all-features

test-verbose:
    cargo test --workspace -- --nocapture

lint:
    cargo clippy --workspace --all-features -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

audit:
    cargo audit
    cargo deny check

coverage:
    cargo tarpaulin --workspace --out Html --output-dir coverage/

bench:
    cargo bench --workspace

ci: fmt-check lint test

all: fmt lint test build

run *ARGS:
    cargo run --release -- {{ARGS}}

clean:
    cargo clean
    rm -rf coverage/

docker-build:
    docker build -t zeus:latest .

setup:
    cargo install just cargo-tarpaulin cargo-audit cargo-deny