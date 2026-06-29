//! End-to-end tests for the `zeus` binary.
//!
//! These tests compile and run the real binary through `std::process::Command`
//! to verify that the CLI surface works correctly from a user's perspective.

use std::process::Command;

fn zeus_bin() -> Command {
    // `cargo test` sets CARGO_BIN_EXE_zeus when the binary is declared in Cargo.toml.
    let path = env!("CARGO_BIN_EXE_zeus");
    Command::new(path)
}

// ── --help / --version ────────────────────────────────────────────────────────

#[test]
fn help_flag_exits_zero() {
    let out = zeus_bin()
        .arg("--help")
        .output()
        .expect("failed to spawn zeus");
    assert!(out.status.success(), "zeus --help exited non-zero");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("zeus"),
        "help output should contain binary name"
    );
}

#[test]
fn version_flag_exits_zero() {
    let out = zeus_bin()
        .arg("--version")
        .output()
        .expect("failed to spawn zeus");
    assert!(out.status.success(), "zeus --version exited non-zero");
}

// ── list subcommand ───────────────────────────────────────────────────────────

#[test]
fn list_subcommand_exits_zero() {
    let out = zeus_bin()
        .arg("list")
        .output()
        .expect("failed to spawn zeus list");
    assert!(
        out.status.success(),
        "zeus list exited {:?}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn list_subcommand_produces_output() {
    let out = zeus_bin()
        .arg("list")
        .output()
        .expect("failed to spawn zeus list");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.is_empty(), "zeus list should print something");
}

// ── attack — missing required args ────────────────────────────────────────────

#[test]
fn attack_without_args_exits_nonzero() {
    let out = zeus_bin()
        .arg("attack")
        .output()
        .expect("failed to spawn zeus attack");
    assert!(
        !out.status.success(),
        "zeus attack without required args should exit non-zero"
    );
}

#[test]
fn attack_missing_target_exits_nonzero() {
    // -p, -U, -P present but -t missing
    let out = zeus_bin()
        .args(["attack", "-p", "ssh", "-U", "u.txt", "-P", "p.txt"])
        .output()
        .expect("failed to spawn");
    assert!(!out.status.success());
}

// ── probe subcommand ──────────────────────────────────────────────────────────

#[test]
fn probe_help_exits_zero() {
    let out = zeus_bin()
        .args(["probe", "--help"])
        .output()
        .expect("failed to spawn");
    assert!(out.status.success());
}

// ── unknown subcommand ────────────────────────────────────────────────────────

#[test]
fn unknown_subcommand_exits_nonzero() {
    let out = zeus_bin()
        .arg("doesnotexist")
        .output()
        .expect("failed to spawn");
    assert!(!out.status.success());
}
