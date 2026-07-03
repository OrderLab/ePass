use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command;

const KNOWN_FALCO_FAILURES: &[&str] = &[
    // libbpf poison/dummy path leaves a dead def in these large programs
    "prog195.txt",
    "prog198.txt",
    // prog286: after spilling 18 values, the remaining oversized clique
    // consists entirely of reload temps (protected from re-spilling).
    // This means the program genuinely needs >10 registers at some point.
    "prog286.txt",
];

fn have_timeout() -> bool {
    Command::new("sh")
        .arg("-c")
        .arg("command -v timeout >/dev/null 2>&1")
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[test]
fn falco_dump_corpus_rewrites_except_known_failures() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let falco = manifest.parent().unwrap().join("bpftests/falco");
    if !falco.exists() {
        eprintln!("skipping falco tests: {} does not exist", falco.display());
        return;
    }

    let mut files: Vec<_> = std::fs::read_dir(&falco)
        .expect("read falco dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("txt"))
        .collect();
    files.sort();

    if files.is_empty() {
        eprintln!("skipping falco tests: no .txt programs in {}", falco.display());
        return;
    }

    let known: HashSet<&str> = KNOWN_FALCO_FAILURES.iter().copied().collect();
    let epasstool = env!("CARGO_BIN_EXE_epasstool");
    let out = std::env::temp_dir().join(format!("epass-falco-{}.dump", std::process::id()));
    let use_timeout = have_timeout();

    let mut passed = 0usize;
    let mut known_failed = 0usize;
    let mut unexpected = Vec::new();

    for file in files {
        let name = file.file_name().unwrap().to_string_lossy().to_string();
        let output = if use_timeout {
            Command::new("timeout")
                .arg("-k")
                .arg("2")
                .arg("10")
                .arg(epasstool)
                .arg("read")
                .arg("-F")
                .arg("log")
                .arg("-o")
                .arg(&out)
                .arg(&file)
                .output()
                .expect("run epasstool with timeout")
        } else {
            Command::new(epasstool)
                .arg("read")
                .arg("-F")
                .arg("log")
                .arg("-o")
                .arg(&out)
                .arg(&file)
                .output()
                .expect("run epasstool")
        };
        if output.status.success() {
            passed += 1;
        } else if known.contains(name.as_str()) {
            known_failed += 1;
        } else {
            unexpected.push(format!(
                "{}: rc={:?}\nstdout={}\nstderr={}",
                name,
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    let _ = std::fs::remove_file(&out);

    eprintln!(
        "falco corpus: passed={} known_failed={} unexpected_failed={}",
        passed,
        known_failed,
        unexpected.len()
    );
    assert!(unexpected.is_empty(), "unexpected Falco failures:\n{}", unexpected.join("\n\n"));
}
