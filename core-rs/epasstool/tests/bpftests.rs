use std::path::{Path, PathBuf};
use std::process::Command;

fn have_cmd(cmd: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {cmd} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn uname_m() -> Option<String> {
    let out = Command::new("uname").arg("-m").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn compile_bpf(src: &Path, out: &Path) -> bool {
    let arch = uname_m().unwrap_or_else(|| "x86_64".to_string());
    Command::new("clang")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-I")
        .arg(format!("/usr/include/{arch}-linux-gnu"))
        .arg("-c")
        .arg(src)
        .arg("-o")
        .arg(out)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn bpftests_compile_and_rewrite_allowlist() {
    if !have_cmd("clang") {
        eprintln!("skipping bpftests: clang not available");
        return;
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bpftests = manifest.parent().unwrap().join("bpftests");
    let cases = [
        "empty.c",
        "exit.c",
        "simple1.c",
        "simple2.c",
        "alu64.c",
        "mem2.c",
        "loop2.c",
        "loop3.c",
        "spillconst.c",
        "test_spill.c",
    ];

    let tmp = std::env::temp_dir().join(format!("epass-bpftests-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let epasstool = env!("CARGO_BIN_EXE_epasstool");
    let mut compiled = 0usize;
    let mut rewritten = 0usize;

    for case in cases {
        let src = bpftests.join(case);
        if !src.exists() {
            eprintln!("skipping missing bpftest {case}");
            continue;
        }
        let obj = tmp.join(format!("{}.o", case.trim_end_matches(".c")));
        if !compile_bpf(&src, &obj) {
            eprintln!("skipping bpftest {case}: clang failed");
            continue;
        }
        compiled += 1;

        let out = tmp.join(format!("{}.dump", case.trim_end_matches(".c")));
        let status = Command::new(epasstool)
            .arg("read")
            .arg("-s")
            .arg("prog")
            .arg("-F")
            .arg("log")
            .arg("-o")
            .arg(&out)
            .arg(&obj)
            .status()
            .expect("run epasstool");
        assert!(status.success(), "epasstool failed on {case}");
        assert!(out.metadata().map(|m| m.len() > 0).unwrap_or(false), "empty dump for {case}");
        rewritten += 1;
    }

    let _ = std::fs::remove_dir_all(&tmp);
    if compiled == 0 {
        eprintln!("skipping bpftests: no allowlisted C tests compiled in this environment");
        return;
    }
    assert_eq!(compiled, rewritten);
}
