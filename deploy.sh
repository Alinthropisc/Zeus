#!/usr/bin/env bash

set -euo pipefail

ZEUS_VERSION="1.0.0"
DIST_DIR="dist"
PACKAGE_NAME="zeus-${ZEUS_VERSION}"
BUILD_DIR="build"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
  echo -e "${GREEN}[INFO]${NC}  $*";
}
log_warn() {
  echo -e "${YELLOW}[WARN]${NC}  $*";
   }
log_error() {
  echo -e "${RED}[ERROR]${NC} $*" >&2;
}
log_section() {
  echo -e "\n${BLUE}══ $* ══${NC}";
}

usage() {
    cat <<EOF
deploy.sh — Zeus deployment script v${ZEUS_VERSION}

Usage: $0 [command] [options]

Commands:
  build       Build C23 project (Release)
  build-debug Build C23 project (Debug + ASan)
  test        Run all tests
  bench       Run benchmarks
  package     Create distribution package
  clean       Clean build artifacts
  install     Install to system (requires sudo)
  docker      Build Docker image
  all         build + test + package

Options:
  --prefix PATH    Install prefix (default: /usr/local)
  --jobs N         Parallel build jobs (default: nproc)
  --no-color       Disable colored output
EOF
}

check_deps() {
    log_section "Checking dependencies"

    local missing=0

    for dep in cmake gcc make pkg-config openssl; do
        if command -v "$dep" &>/dev/null; then
            log_info "✓ $dep"
        else
            log_error "✗ $dep not found"
            ((missing++))
        fi
    done

    # проверить версию GCC (нужен C23 ≥ GCC 14 или Clang 18)
    if command -v gcc &>/dev/null; then
        local gcc_ver
        gcc_ver=$(gcc -dumpversion | cut -d. -f1)
        if [[ "$gcc_ver" -ge 14 ]]; then
            log_info "✓ GCC $gcc_ver (C23 support)"
        else
            log_warn "GCC $gcc_ver found, C23 requires GCC ≥ 14"
            log_warn "Trying clang..."
            if command -v clang &>/dev/null; then
                local clang_ver
                clang_ver=$(clang -dumpversion | cut -d. -f1)
                if [[ "$clang_ver" -ge 18 ]]; then
                    log_info "✓ Clang $clang_ver (C23 support)"
                    export CC=clang
                else
                    log_error "Clang $clang_ver too old for C23"
                    ((missing++))
                fi
            fi
        fi
    fi

    # опциональные библиотеки
    log_section "Optional libraries"
    for lib in libssl-dev libssh-dev libfreerdp2-dev \
               libmysqlclient-dev libpq-dev libpcre2-dev \
               libmemcached-dev firebird-dev; do
        if pkg-config --exists "${lib%-dev}" 2>/dev/null; then
            log_info "✓ $lib"
        else
            log_warn "○ $lib (optional, feature disabled)"
        fi
    done

    if [[ $missing -gt 0 ]]; then
        log_error "Missing $missing required dependencies"
        exit 1
    fi
}

# ─── build ────────────────────────────────────────────────────────────────────
build() {
    local build_type="${1:-Release}"
    local jobs
    jobs="${JOBS:-$(nproc)}"

    log_section "Building Zeus (${build_type})"

    mkdir -p "${BUILD_DIR}"
    pushd "${BUILD_DIR}" > /dev/null

    cmake .. \
        -DCMAKE_BUILD_TYPE="${build_type}" \
        -DCMAKE_C_COMPILER="${CC:-gcc}" \
        -DCMAKE_INSTALL_PREFIX="${PREFIX:-/usr/local}" \
        -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

    make -j"${jobs}" VERBOSE=0

    popd > /dev/null
    log_info "Build complete: ${BUILD_DIR}/zeus"
}

# ─── test ─────────────────────────────────────────────────────────────────────
run_tests() {
    log_section "Running tests"

    if [[ ! -d "${BUILD_DIR}" ]]; then
        log_error "Build directory not found, run build first"
        exit 1
    fi

    pushd "${BUILD_DIR}" > /dev/null
    ctest --output-on-failure --parallel "$(nproc)"
    popd > /dev/null

    log_info "All tests passed"
}

# ─── benchmark ────────────────────────────────────────────────────────────────
run_bench() {
    log_section "Running benchmarks"

    if [[ ! -f "${BUILD_DIR}/zeus" ]]; then
        log_error "Binary not found, run build first"
        exit 1
    fi

    # C23 vs Rust comparison
    if command -v cargo &>/dev/null && [[ -d "../zeus-rust" ]]; then
        log_info "Building Rust version..."
        pushd ../zeus-rust > /dev/null
        cargo build --release 2>/dev/null
        popd > /dev/null

        log_info "Running parallel benchmarks..."
        log_info "C23:  $(${BUILD_DIR}/zeus --version 2>/dev/null || echo 'zeus')"
        log_info "Rust: $(../zeus-rust/target/release/zeus --version 2>/dev/null || echo 'zeus-rust')"
    fi
}

# ─── package ──────────────────────────────────────────────────────────────────
create_package() {
    log_section "Creating distribution package"

    mkdir -p "${DIST_DIR}/${PACKAGE_NAME}"

    # бинарники
    if [[ -f "${BUILD_DIR}/zeus" ]]; then
        cp "${BUILD_DIR}/zeus"              "${DIST_DIR}/${PACKAGE_NAME}/"
        cp "${BUILD_DIR}/zeus-pw-inspector" "${DIST_DIR}/${PACKAGE_NAME}/" 2>/dev/null || true
    fi

    # документация
    cp README.md   "${DIST_DIR}/${PACKAGE_NAME}/" 2>/dev/null || true
    cp LICENSE     "${DIST_DIR}/${PACKAGE_NAME}/" 2>/dev/null || true
    cp CHANGELOG   "${DIST_DIR}/${PACKAGE_NAME}/" 2>/dev/null || true

    # скрипты
    cp dpl4zeus.sh "${DIST_DIR}/${PACKAGE_NAME}/"

    # создать архив
    pushd "${DIST_DIR}" > /dev/null
    tar czf "${PACKAGE_NAME}.tar.gz" "${PACKAGE_NAME}/"
    sha256sum "${PACKAGE_NAME}.tar.gz" > "${PACKAGE_NAME}.tar.gz.sha256"
    popd > /dev/null

    log_info "Package: ${DIST_DIR}/${PACKAGE_NAME}.tar.gz"
    log_info "SHA256:  $(cat "${DIST_DIR}/${PACKAGE_NAME}.tar.gz.sha256")"
}

# ─── install ──────────────────────────────────────────────────────────────────
do_install() {
    local prefix="${PREFIX:-/usr/local}"
    log_section "Installing to ${prefix}"

    if [[ ! -f "${BUILD_DIR}/zeus" ]]; then
        log_error "Binary not found, run build first"
        exit 1
    fi

    install -Dm755 "${BUILD_DIR}/zeus" "${prefix}/bin/zeus"
    install -Dm755 "${BUILD_DIR}/zeus-pw-inspector" \
        "${prefix}/bin/zeus-pw-inspector" 2>/dev/null || true

    log_info "Installed: ${prefix}/bin/zeus"
}

# ─── docker ───────────────────────────────────────────────────────────────────
build_docker() {
    log_section "Building Docker image"

    cat > Dockerfile.zeus <<'DOCKERFILE'
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc-14 cmake make pkg-config \
    libssl-dev libssh-dev libpcre2-dev \
    libmysqlclient-dev libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /zeus
COPY . .

RUN mkdir build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release \
             -DCMAKE_C_COMPILER=gcc-14 && \
    make -j"$(nproc)"

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libssh-4 libpcre2-8-0 \
    libmysqlclient21 libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=0 /zeus/build/zeus /usr/local/bin/zeus
ENTRYPOINT ["/usr/local/bin/zeus"]
DOCKERFILE

    docker build -f Dockerfile.zeus -t "zeus:${ZEUS_VERSION}" .
    log_info "Docker image: zeus:${ZEUS_VERSION}"
}

do_clean() {
    log_section "Cleaning"
    rm -rf "${BUILD_DIR}" "${DIST_DIR}"
    log_info "Clean complete"
}

COMMAND="${1:-help}"
JOBS="${JOBS:-}"
PREFIX="${PREFIX:-/usr/local}"

# разобрать опции
while [[ $# -gt 1 ]]; do
    case "$2" in
        --prefix) PREFIX="$3"; shift 2 ;;
        --jobs)   JOBS="$3";   shift 2 ;;
        --no-color) RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''; shift ;;
        *) shift ;;
    esac
done

case "$COMMAND" in
    build)       check_deps && build Release ;;
    build-debug) check_deps && build Debug ;;
    test)        run_tests ;;
    bench)       run_bench ;;
    package)     create_package ;;
    clean)       do_clean ;;
    install)     do_install ;;
    docker)      build_docker ;;
    all)
        check_deps
        build Release
        run_tests
        create_package
        ;;
    help|--help|-h) usage ;;
    *)
        log_error "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac