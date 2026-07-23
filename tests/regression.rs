use rusqlite::Connection;
use serde_json::Value as JsonValue;
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};
use toml::Value as TomlValue;

const REGRESSION_YARA_RULES: &str = r#"
rule GALEN_Regression_EICAR_Test_File
{
    meta:
        description = "Regression-only EICAR test rule"
        category = "test-file"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

rule GALEN_Regression_EICAR_Archive_Test
{
    meta:
        description = "Second regression-only EICAR rule so EICAR fixtures score malicious"
        category = "test-file"

    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii

    condition:
        $eicar
}

rule GALEN_Regression_EICAR_Weaker_Child
{
    meta:
        description = "Regression rule for a suspicious archive child"
        category = "test-file"

    strings:
        $marker = "GALEN_WEAKER_CHILD_MARKER" ascii

    condition:
        $marker
}

rule GALEN_Regression_EICAR_Container_Only
{
    meta:
        description = "Regression rule stored only in the archive comment"
        category = "test-file"

    strings:
        $marker = "GALEN_CONTAINER_ONLY_MARKER" ascii

    condition:
        $marker
}
"#;

/// Runs the generated corpus regression suite through the compiled CLI.
#[test]
#[ignore = "explicit regression suite; run with `cargo test --test regression -- --ignored`"]
fn generated_corpus_regression_suite() {
    let mode = RegressionMode::from_env();
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace = tempfile::tempdir().expect("create regression workspace");
    let binary = galen_binary();

    let database = workspace.path().join("signatures.sqlite");
    create_empty_database(&database);

    let yara_cache = workspace.path().join("galen-regression.yaraxc");
    write_yara_cache(&yara_cache);

    let corpus = workspace.path().join("corpus");
    generate_corpus(&repo, &corpus);
    let manifest = read_manifest(&corpus);

    let runner = ScanRunner {
        binary,
        database,
        yara_cache,
    };

    run_smoke_regression(&runner, &corpus, &manifest);

    if mode == RegressionMode::Full {
        run_full_corpus_regression(&runner, &corpus, &manifest);
        run_system_false_positive_regression(&runner);
    }

    run_symlink_loop_regression(&runner, workspace.path());
}

/// Selects the amount of regression coverage to run in this invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegressionMode {
    Smoke,
    Full,
}

impl RegressionMode {
    /// Reads the regression mode from the environment.
    fn from_env() -> Self {
        match env::var("GALEN_REGRESSION_MODE").as_deref() {
            Ok("full") => Self::Full,
            Ok("smoke") | Err(_) => Self::Smoke,
            Ok(other) => panic!("unsupported GALEN_REGRESSION_MODE: {other}"),
        }
    }
}

/// Holds the scanner binary and temporary runtime inputs used by regression scans.
struct ScanRunner {
    binary: PathBuf,
    database: PathBuf,
    yara_cache: PathBuf,
}

impl ScanRunner {
    /// Runs Galen against one target and parses its JSON report.
    fn scan(&self, target: impl AsRef<Path>) -> ScanOutput {
        let output = Command::new(&self.binary)
            .arg("scan")
            .arg(target.as_ref())
            .arg("--database")
            .arg(&self.database)
            .arg("--yara-cache")
            .arg(&self.yara_cache)
            .arg("--output")
            .arg("json")
            .output()
            .unwrap_or_else(|err| {
                panic!("run galen scan for {}: {err}", target.as_ref().display())
            });

        let stdout = String::from_utf8(output.stdout).expect("scan stdout is UTF-8");
        let stderr = String::from_utf8(output.stderr).expect("scan stderr is UTF-8");
        let json = serde_json::from_str(&stdout).unwrap_or_else(|err| {
            panic!(
                "scan stdout was not valid JSON for {}\nerr: {err}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                target.as_ref().display()
            )
        });

        ScanOutput {
            code: output.status.code().unwrap_or(-1),
            json,
            stdout,
            stderr,
        }
    }
}

/// Captures a Galen scan process result and its parsed JSON report.
struct ScanOutput {
    code: i32,
    json: JsonValue,
    stdout: String,
    stderr: String,
}

impl ScanOutput {
    /// Asserts that the JSON report is a completed scan report.
    fn assert_status_ok(&self, label: &str) {
        assert_eq!(
            self.json["status"].as_str(),
            Some("ok"),
            "{label}: expected successful JSON report\nstdout:\n{}\nstderr:\n{}",
            self.stdout,
            self.stderr
        );
    }

    /// Returns the visible detection records from a scan report.
    fn visible_detections(&self) -> &[JsonValue] {
        self.json["visible_detections"]
            .as_array()
            .expect("visible_detections is an array")
    }

    /// Returns the skip records from a scan report.
    fn skips(&self) -> &[JsonValue] {
        self.json["summary"]["skips"]
            .as_array()
            .expect("summary.skips is an array")
    }

    /// Reports whether the scan produced the requested skip reason.
    fn has_skip_reason(&self, reason: &str) -> bool {
        self.skips()
            .iter()
            .any(|skip| skip["reason"].as_str() == Some(reason))
    }

    /// Returns the highest visible verdict found in the report.
    fn max_visible_verdict(&self) -> Option<&str> {
        self.visible_detections()
            .iter()
            .filter_map(|detection| detection["verdict"].as_str())
            .max_by_key(|verdict| verdict_rank(verdict))
    }

    /// Reports whether any detection path points inside an archive.
    fn has_inner_archive_detection(&self) -> bool {
        self.visible_detections()
            .iter()
            .chain(
                self.json["suppressed_detections"]
                    .as_array()
                    .expect("suppressed_detections is an array")
                    .iter(),
            )
            .filter_map(|detection| detection["path"].as_str())
            .any(|path| path.contains("!/"))
    }
}

/// Runs the bounded smoke set used by normal CI.
fn run_smoke_regression(runner: &ScanRunner, corpus: &Path, manifest: &TomlValue) {
    assert_manifest_has_group(manifest, "clean");
    assert_manifest_has_group(manifest, "synthetic-malicious");
    assert_manifest_has_group(manifest, "archive-malicious");
    assert_manifest_has_group(manifest, "malformed");
    assert_manifest_has_case(manifest, "controlled-zip-bomb");
    assert_manifest_has_case(
        manifest,
        "verdict-suppression-preserves-malicious-container",
    );
    assert_manifest_has_case(manifest, "symlink-no-follow");
    assert_manifest_has_case(manifest, "zip-entry-count-preflight");

    assert_clean_scan(runner, &corpus.join("clean"), "clean smoke corpus");
    assert_malicious_scan(
        runner,
        &corpus.join("malicious/synthetic/eicar/eicar.com"),
        false,
        "synthetic EICAR file",
    );
    assert_malicious_scan(
        runner,
        &corpus.join("archives/malicious/eicar_zip.zip"),
        true,
        "EICAR zip archive",
    );
    assert_malformed_scan(
        runner,
        &corpus.join("malformed/zip/truncated.zip"),
        "truncated zip",
    );
    assert_skip_scan(
        runner,
        &corpus.join("stress/decompression_limits/zip_bomb_controlled.zip"),
        "maximum_decompressed_size_reached",
        "controlled zip bomb",
    );
    assert_malicious_container_preserved(
        runner,
        &corpus
            .join("security_regressions/verdict_suppression/malicious_container_weaker_child.zip"),
        "verdict suppression regression",
    );
    assert_skip_scan(
        runner,
        &corpus.join("security_regressions/symlinks/malicious-link.bin"),
        "file_is_symlink",
        "symlink no-follow regression",
    );
    assert_zip_entry_preflight_skip(
        runner,
        &corpus.join("security_regressions/zip_limits/declared_10001_entries.zip"),
        "ZIP entry-count preflight regression",
    );
}

/// Runs the full generated corpus according to the manifest groups and cases.
fn run_full_corpus_regression(runner: &ScanRunner, corpus: &Path, manifest: &TomlValue) {
    for group in group_entries(manifest) {
        let id = group["id"].as_str().expect("group id is a string");
        let root = group["root"].as_str().expect("group root is a string");
        let root_path = corpus.join(root);

        match id {
            "clean" | "archive-clean" => assert_clean_scan(runner, &root_path, id),
            "suspicious-benign" | "archive-suspicious" => {
                for file in collect_files(&root_path) {
                    assert_at_most_suspicious_scan(runner, &file, id);
                }
            }
            "synthetic-malicious" | "archive-malicious" | "archive-mixed" => {
                for file in collect_files(&root_path) {
                    let expect_inner_path = id.starts_with("archive-")
                        || matches!(
                            file.extension().and_then(|extension| extension.to_str()),
                            Some("zip" | "tar" | "gz")
                        );
                    assert_malicious_scan(runner, &file, expect_inner_path, id);
                }
            }
            "malformed" => {
                for file in collect_files(&root_path) {
                    assert_malformed_scan(runner, &file, id);
                }
            }
            "stress" | "security-regressions" => {}
            other => panic!("unhandled regression manifest group: {other}"),
        }
    }

    for case in case_entries(manifest) {
        let id = case["id"].as_str().expect("case id is a string");
        let path = case["path"].as_str().expect("case path is a string");
        let target = corpus.join(path);

        match id {
            "eicar-zip-inside-tar-gz" | "eicar-tar-gz-inside-zip" => {
                assert_malicious_scan(runner, &target, true, id);
            }
            "deep-recursion-limit" | "deep-large-recursion-limit" => {
                assert_skip_scan(runner, &target, "maximum_recursion_reached", id);
            }
            "controlled-zip-bomb" => {
                assert_skip_scan(runner, &target, "maximum_decompressed_size_reached", id);
            }
            "verdict-suppression-preserves-malicious-container" => {
                assert_malicious_container_preserved(runner, &target, id);
            }
            "symlink-no-follow" => {
                assert_skip_scan(runner, &target, "file_is_symlink", id);
            }
            "zip-entry-count-preflight" => {
                assert_zip_entry_preflight_skip(runner, &target, id);
            }
            other => panic!("unhandled regression manifest case: {other}"),
        }
    }
}

/// Scans selected distro system paths to catch broad false-positive regressions.
fn run_system_false_positive_regression(runner: &ScanRunner) {
    let targets = existing_system_scan_targets();
    assert!(
        !targets.is_empty(),
        "system false-positive regression did not find any distro directories to scan"
    );

    for path in targets {
        assert_system_path_has_no_flagged_files(
            runner,
            &path,
            &format!("system false-positive scan {}", path.display()),
        );
    }
}

/// Asserts that a distro system path reports no JSON detection records.
fn assert_system_path_has_no_flagged_files(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert_eq!(
        result.code, 0,
        "{label}: system scan should exit 0\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    assert_eq!(
        result.json["summary"]["raw_detection_records"].as_u64(),
        Some(0),
        "{label}: expected zero raw detection records\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert_eq!(
        result.json["summary"]["visible_detection_records"].as_u64(),
        Some(0),
        "{label}: expected zero visible detection records\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert_eq!(
        result.json["summary"]["suppressed_detection_records"].as_u64(),
        Some(0),
        "{label}: expected zero suppressed detection records\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert!(
        result.visible_detections().is_empty(),
        "{label}: expected no visible detection entries\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}

/// Creates and scans a symlink loop fixture to ensure the scanner does not follow it.
fn run_symlink_loop_regression(runner: &ScanRunner, workspace: &Path) {
    #[cfg(not(unix))]
    panic!("symlink loop regression requires Unix symlink semantics");

    #[cfg(unix)]
    {
        let root = workspace.join("symlink-loop");
        fs::create_dir_all(&root).expect("create symlink loop fixture");
        fs::write(root.join("clean.txt"), "clean symlink loop control\n")
            .expect("write clean control");
        std::os::unix::fs::symlink(&root, root.join("loop")).expect("create symlink loop");

        let result = runner.scan(&root);
        result.assert_status_ok("symlink loop");
        assert_eq!(result.code, 0, "symlink loop scan should not fail");
        assert!(
            result.has_skip_reason("file_is_symlink"),
            "symlink loop should record file_is_symlink skip\nstdout:\n{}\nstderr:\n{}",
            result.stdout,
            result.stderr
        );
    }
}

/// Asserts that a target completes without visible detections.
fn assert_clean_scan(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert_eq!(
        result.code, 0,
        "{label}: clean scan should exit 0\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    assert!(
        result.visible_detections().is_empty(),
        "{label}: expected no visible detections\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}

/// Asserts that a suspicious control target does not escalate above suspicious.
fn assert_at_most_suspicious_scan(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert!(
        result.code == 0 || result.code == 1,
        "{label}: suspicious control scan should exit 0 or 1\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );

    if let Some(verdict) = result.max_visible_verdict() {
        assert!(
            verdict_rank(verdict) <= verdict_rank("suspicious"),
            "{label}: suspicious control escalated to {verdict}\nstdout:\n{}\nstderr:\n{}",
            result.stdout,
            result.stderr
        );
    }
}

/// Asserts that a target produces a visible malicious detection.
fn assert_malicious_scan(runner: &ScanRunner, target: &Path, expect_inner_path: bool, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert_eq!(
        result.code, 1,
        "{label}: malicious scan should exit 1\nstdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
    assert!(
        result
            .visible_detections()
            .iter()
            .any(|detection| detection["verdict"].as_str() == Some("malicious")),
        "{label}: expected a visible malicious detection\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );

    if expect_inner_path {
        assert!(
            result.has_inner_archive_detection(),
            "{label}: expected detection path inside an archive\nstdout:\n{}\nstderr:\n{}",
            result.stdout,
            result.stderr
        );
    }
}

/// Asserts that a weaker archive child cannot suppress its malicious container.
fn assert_malicious_container_preserved(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert_eq!(result.code, 1, "{label}: expected detection exit code");

    let target_path = target.to_string_lossy();
    assert!(
        result.visible_detections().iter().any(|detection| {
            detection["path"].as_str() == Some(target_path.as_ref())
                && detection["verdict"].as_str() == Some("malicious")
                && detection["surface"].as_str() == Some("archive_container")
        }),
        "{label}: malicious container was not visible\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}

/// Asserts that an excessive ZIP footer count is rejected before any entries are parsed.
fn assert_zip_entry_preflight_skip(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert!(
        result.has_skip_reason("maximum_archive_entries_reached"),
        "{label}: expected maximum_archive_entries_reached skip\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert_eq!(
        result.json["summary"]["archive_entries"].as_u64(),
        Some(0),
        "{label}: ZIP central directory entries were parsed before rejection\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}

/// Asserts that a malformed fixture is handled without high-confidence detection.
fn assert_malformed_scan(runner: &ScanRunner, target: &Path, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert!(
        result.code == 0 || result.code == 2,
        "{label}: malformed fixture should complete or report an operational scan error\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );

    if let Some(verdict) = result.max_visible_verdict() {
        assert!(
            verdict_rank(verdict) <= verdict_rank("suspicious"),
            "{label}: malformed fixture escalated to {verdict}\nstdout:\n{}\nstderr:\n{}",
            result.stdout,
            result.stderr
        );
    }
}

/// Asserts that a target records the expected skip reason.
fn assert_skip_scan(runner: &ScanRunner, target: &Path, reason: &str, label: &str) {
    let result = runner.scan(target);
    result.assert_status_ok(label);
    assert!(
        result.code == 0 || result.code == 1,
        "{label}: skip fixture should not be an operational error\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
    assert!(
        result.has_skip_reason(reason),
        "{label}: expected skip reason {reason}\nstdout:\n{}\nstderr:\n{}",
        result.stdout,
        result.stderr
    );
}

/// Creates the empty SQLite hash database required by the scan command.
fn create_empty_database(path: &Path) {
    let connection = Connection::open(path).expect("create empty signature database");
    connection
        .execute("CREATE TABLE malware_hashes (sha256 BLOB NOT NULL)", [])
        .expect("create malware_hashes table");
}

/// Compiles the regression-only YARA rules into a temporary cache.
fn write_yara_cache(path: &Path) {
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(REGRESSION_YARA_RULES)
        .expect("compile regression YARA source");
    let rules = compiler.build();
    let file = fs::File::create(path).expect("create YARA cache");
    let writer = io::BufWriter::new(file);
    rules.serialize_into(writer).expect("serialize YARA cache");
}

/// Generates the regression corpus in a temporary directory.
fn generate_corpus(repo: &Path, corpus: &Path) {
    let status = Command::new("bash")
        .arg(repo.join("scripts/corpus/generate.sh"))
        .arg(corpus)
        .current_dir(repo)
        .status()
        .expect("run corpus generator");

    assert!(status.success(), "corpus generator failed with {status}");
}

/// Reads the generated corpus manifest.
fn read_manifest(corpus: &Path) -> TomlValue {
    let manifest =
        fs::read_to_string(corpus.join("manifest.toml")).expect("read regression manifest");
    toml::from_str(&manifest).expect("parse regression manifest")
}

/// Returns the manifest group entries.
fn group_entries(manifest: &TomlValue) -> &[TomlValue] {
    manifest["group"].as_array().expect("manifest groups array")
}

/// Returns the manifest case entries.
fn case_entries(manifest: &TomlValue) -> &[TomlValue] {
    manifest["case"].as_array().expect("manifest cases array")
}

/// Asserts that the generated manifest contains a named group.
fn assert_manifest_has_group(manifest: &TomlValue, id: &str) {
    assert!(
        group_entries(manifest)
            .iter()
            .any(|group| group["id"].as_str() == Some(id)),
        "manifest is missing group {id}"
    );
}

/// Asserts that the generated manifest contains a named case.
fn assert_manifest_has_case(manifest: &TomlValue, id: &str) {
    assert!(
        case_entries(manifest)
            .iter()
            .any(|case| case["id"].as_str() == Some(id)),
        "manifest is missing case {id}"
    );
}

/// Collects regular files below a root path in stable order.
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    collect_files_recursive(root, &mut files);
    files.sort();
    files
}

/// Recursively appends regular files while ignoring symlinks.
fn collect_files_recursive(path: &Path, files: &mut Vec<PathBuf>) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|err| panic!("read metadata for {}: {err}", path.display()));

    if metadata.file_type().is_symlink() {
        return;
    }

    if metadata.is_file() {
        files.push(path.to_path_buf());
        return;
    }

    if metadata.is_dir() {
        for entry in
            fs::read_dir(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
        {
            let entry =
                entry.unwrap_or_else(|err| panic!("read entry below {}: {err}", path.display()));
            collect_files_recursive(&entry.path(), files);
        }
    }
}

/// Returns bounded system paths that exist in the current distro image.
fn existing_system_scan_targets() -> Vec<PathBuf> {
    [
        "/etc",
        "/usr/bin",
        "/usr/sbin",
        "/usr/lib",
        "/usr/lib64",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/opt",
    ]
    .into_iter()
    .map(PathBuf::from)
    .filter(|path| path.is_dir() && !path.is_symlink())
    .collect()
}

/// Resolves the Galen binary path used by the regression test.
fn galen_binary() -> PathBuf {
    env::var_os("GALEN_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_galen")))
}

/// Maps JSON verdict labels into an ordering for assertions.
fn verdict_rank(verdict: &str) -> u8 {
    match verdict {
        "clean" => 0,
        "informational" => 1,
        "suspicious" => 2,
        "likely_malicious" => 3,
        "malicious" => 4,
        other => panic!("unknown verdict: {other}"),
    }
}
