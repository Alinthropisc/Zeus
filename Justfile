default:
    just --list

build:
    cargo build --release

dev:
    cargo build

test:
    cargo test --all-features

lint:
    cargo clippy --all-features -- -D warnings

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

bench:
    cargo bench

clean:
    cargo clean
    find . -name "*.o" -delete

run-as-root *ARGS:
    sudo ./target/release/azula {{ARGS}}

check: fmt-check lint test
    @echo "✅ All checks passed"