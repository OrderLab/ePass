//! epasstool end to end: every input kind, every command, the Falco corpus
//! and the bpftests ELF objects.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tool(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_epasstool")).args(args).output().expect("run epasstool")
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("epasstool-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d.join(name)
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

fn dump(path: &Path) -> Vec<u64> {
    std::fs::read_to_string(path).unwrap().lines().map(|l| l.trim().parse().unwrap()).collect()
}

#[test]
fn usage_errors_exit_2() {
    assert_eq!(tool(&[]).status.code(), Some(2));
    assert_eq!(tool(&["frob", "x"]).status.code(), Some(2));
    assert_eq!(tool(&["read"]).status.code(), Some(2));
    assert_eq!(tool(&["read", "-F", "nope", "x"]).status.code(), Some(2));
}

#[test]
fn ir_round_trips_and_compiles() {
    let prog = root().join("bpftests/falco/prog10.txt");
    if !prog.exists() {
        return;
    }
    let (t1, b, t2) = (tmp("p.epir"), tmp("p.blob"), tmp("q.epir"));
    assert!(tool(&["lift", s(&prog), "-o", s(&t1)]).status.success());
    assert!(tool(&["convert", s(&t1), "-o", s(&b)]).status.success());
    assert!(tool(&["convert", s(&b), "-o", s(&t2)]).status.success());
    assert_eq!(std::fs::read(&t1).unwrap(), std::fs::read(&t2).unwrap());
    assert!(std::fs::read(&b).unwrap().starts_with(b"EPIR"));
    // Text IR, blob IR and bytecode all compile.
    for input in [&t1, &b, &prog] {
        let out = tmp("o.txt");
        let r = tool(&["read", "-q", s(input), "-o", s(&out)]);
        assert!(r.status.success(), "{}: {}", input.display(), String::from_utf8_lossy(&r.stderr));
        assert!(!dump(&out).is_empty());
    }
    // Passes only: IR out.
    let r = tool(&["read", "-P", "--popt", "!const_prop", s(&prog)]);
    assert!(r.status.success());
    assert!(String::from_utf8_lossy(&r.stdout).starts_with("; epir v2"));
    // Printing bytecode disassembles.
    let r = tool(&["print", s(&prog)]);
    assert!(String::from_utf8_lossy(&r.stdout).contains("call 1"));
    // Format mismatches are errors.
    assert!(!tool(&["read", "-q", "-F", "epir", s(&prog)]).status.success());
    assert!(!tool(&["lift", "-F", "asm", s(&prog)]).status.success());
}

#[test]
fn options_and_policy_reach_the_core() {
    let prog = root().join("bpftests/falco/prog10.txt");
    if !prog.exists() {
        return;
    }
    let r = tool(&["read", "--gopt", "verbose=2,isa=v4,ra_colors=4", "-F", "asm", s(&prog)]);
    assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
    assert!(String::from_utf8_lossy(&r.stderr).contains("isa v4"));
    let r = tool(&["read", "--gopt", "bogus", s(&prog)]);
    assert!(!r.status.success());
    let r = tool(&["read", "--policy", "-const_prop", "--popt", "const_prop", s(&prog)]);
    assert!(!r.status.success());
    assert!(String::from_utf8_lossy(&r.stderr).contains("denied"));
}

#[test]
fn falco_corpus() {
    let dir = root().join("bpftests/falco");
    if !dir.exists() {
        return;
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.file_name().unwrap().to_str().unwrap().starts_with("prog") && !p.ends_with("progs.txt"))
        .collect();
    files.sort();
    let out = tmp("falco.txt");
    let (mut ok, mut callbacks) = (0, 0);
    for f in &files {
        let r = tool(&["read", "-q", s(f), "-o", s(&out)]);
        let err = String::from_utf8_lossy(&r.stderr);
        if r.status.success() {
            ok += 1;
        } else {
            assert!(err.contains("callbacks"), "{}: {err}", f.display());
            callbacks += 1;
        }
    }
    assert!(ok >= 337, "{ok} compiled, {callbacks} callback programs");
}

#[test]
fn bpftests_elf_objects() {
    let have_clang = Command::new("clang").arg("--version").output().is_ok_and(|o| o.status.success());
    if !have_clang {
        eprintln!("skipping: no clang");
        return;
    }
    // Expected rejections, by the error they must report.
    let expected = [("asm.c", "ecall"), ("localcall.c", "bpf-to-bpf")];
    let arch = Command::new("uname").arg("-m").output().map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    let dir = root().join("bpftests");
    let mut cases: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| n.ends_with(".c"))
        .collect();
    cases.sort();
    let (mut compiled, mut ok) = (0, 0);
    for case in &cases {
        let obj = tmp(&case.replace(".c", ".o"));
        let built = Command::new("clang")
            .args(["-O2", "-g", "-target", "bpf", "-I", &format!("/usr/include/{arch}-linux-gnu"), "-I"])
            .arg(&dir)
            .arg("-c")
            .arg(dir.join(case))
            .arg("-o")
            .arg(&obj)
            .output()
            .is_ok_and(|o| o.status.success());
        if !built {
            eprintln!("skipping {case}: clang failed (missing headers?)");
            continue;
        }
        compiled += 1;
        let out = tmp(&case.replace(".c", ".txt"));
        let r = tool(&["read", "-q", "-o", s(&out), s(&obj)]);
        let err = String::from_utf8_lossy(&r.stderr);
        match expected.iter().find(|(n, _)| n == case) {
            Some((_, why)) => assert!(!r.status.success() && err.contains(why), "{case}: expected '{why}', got: {err}"),
            None => {
                assert!(r.status.success(), "{case}: {err}");
                assert!(!dump(&out).is_empty(), "{case}: empty output");
                ok += 1;
            }
        }
    }
    eprintln!("{compiled} bpftests built, {ok} compiled by ePass");
    assert!(compiled == 0 || ok >= 20, "only {ok} of {compiled} compiled");
}
