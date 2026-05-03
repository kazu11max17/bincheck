//! Integration test for `--strict` exit-code semantics (Ren P0-1, F2 spec §3).
//!
//! Validates the contract:
//! - SUID/SGID is informational by default (exit 0)
//! - `--strict` promotes the SUID/SGID warning to exit 1
//! - A clean hardened binary (`/bin/ls` on modern Linux) passes `--strict`
//!
//! Linux-only: Windows reports `NotApplicable` for the file-mode check, so SUID
//! semantics do not apply.

#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

fn bincheck_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bincheck")
}

fn run(args: &[&str]) -> std::process::ExitStatus {
    Command::new(bincheck_bin())
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("failed to spawn bincheck")
}

#[test]
fn strict_exits_zero_for_clean_hardened_binary() {
    // /bin/ls on modern Linux ships with full hardening. If the host distro
    // ever stops shipping a hardened ls this test would flake — that itself is
    // a useful signal, so we keep the assertion strict.
    let status = run(&["--strict", "/bin/ls"]);
    assert!(
        status.success(),
        "expected exit 0 for /bin/ls --strict, got {:?}",
        status.code()
    );
}

#[test]
fn no_strict_exits_zero_for_suid_binary() {
    let path = std::env::temp_dir().join("bincheck_it_suid_lax.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::copy("/bin/ls", &path).expect("copy /bin/ls");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4755)).expect("chmod 4755");

    let status = run(&[path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);

    assert!(
        status.success(),
        "SUID without --strict must stay informational (exit 0), got {:?}",
        status.code()
    );
}

#[test]
fn strict_exits_one_for_suid_binary() {
    let path = std::env::temp_dir().join("bincheck_it_suid_strict.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::copy("/bin/ls", &path).expect("copy /bin/ls");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4755)).expect("chmod 4755");

    let status = run(&["--strict", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        status.code(),
        Some(1),
        "SUID with --strict must exit 1 (warning promoted to failure)"
    );
}

#[test]
fn strict_exits_one_for_sgid_binary() {
    let path = std::env::temp_dir().join("bincheck_it_sgid_strict.bin");
    let _ = std::fs::remove_file(&path);
    std::fs::copy("/bin/ls", &path).expect("copy /bin/ls");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o2755)).expect("chmod 2755");

    let status = run(&["--strict", path.to_str().unwrap()]);
    let _ = std::fs::remove_file(&path);

    assert_eq!(
        status.code(),
        Some(1),
        "SGID with --strict must exit 1 (warning promoted to failure)"
    );
}
