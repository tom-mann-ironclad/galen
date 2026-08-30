# Galen

[![CI](https://github.com/tom-mann-ironclad/galen/actions/workflows/ci.yaml/badge.svg)](https://github.com/tom-mann-ironclad/galen/actions/workflows/ci.yaml)
[![Nightly Packages](https://github.com/tom-mann-ironclad/galen/actions/workflows/nightly.yaml/badge.svg)](https://github.com/tom-mann-ironclad/galen/actions/workflows/nightly.yaml)
[![Code Coverage](https://img.shields.io/endpoint?url=https%3A%2F%2Fpackages.ironclad-software.com%2Fnightly%2Fbadges%2Fcoverage.json&cacheSeconds=3600)](#testing-and-build-assurance)
[![Mutation Score](https://img.shields.io/endpoint?url=https%3A%2F%2Fpackages.ironclad-software.com%2Fnightly%2Fbadges%2Fmutation.json&cacheSeconds=3600)](#testing-and-build-assurance)
![GitHub License](https://img.shields.io/github/license/tom-mann-ironclad/galen)

Galen is an alpha-stage static malware scanner and security intelligence pipeline for Linux, written in Rust.

It combines local hash-based detection, YARA rule scanning, archive inspection, and conservative heuristics into a fast command-line tool designed to be understandable, resource-conscious, and operator-friendly.

> [!IMPORTANT]
> Galen is pre-1.0 security software. Its core scanning pipeline is functional and available for testing, but it has not yet received the breadth of hostile-input testing, malware evaluation, independent review, or operational use associated with mature security products.
>
> Galen should not be used as the only security control on a system.

## Try Galen

Galen is ready for practical evaluation by Linux users, Rust developers, security engineers, and anyone interested in lightweight, inspectable malware scanning.

Useful ways to try it include:

* Scanning clean Linux installations and reporting false positives
* Testing its behaviour against inert EICAR and AMTSO test files
* Exercising nested, malformed, or unusually structured archives
* Measuring performance and memory use on different systems
* Integrating its versioned JSON output into scripts or CI jobs
* Reviewing its scan decisions, safety limits, and operator output
* Testing the nightly APT and DNF packages

Feedback from real systems is valuable, particularly where Galen behaves unexpectedly, produces unclear output, misses an operational error, or consumes more resources than expected.

## Installation

Only nightly development packages are currently available. These packages are intended for evaluation and are not stable releases.

### APT

Create the keyring directory and install the repository signing key:

```sh
sudo mkdir -p /etc/apt/keyrings
sudo curl -fsSL \
  https://packages.ironclad-software.com/packages.gpg \
  -o /etc/apt/keyrings/galen.gpg
```

Add the Galen nightly repository:

```sh
echo "deb [signed-by=/etc/apt/keyrings/galen.gpg] https://packages.ironclad-software.com/nightly/apt /" \
  | sudo tee /etc/apt/sources.list.d/galen.list
```

Install Galen:

```sh
sudo apt update
sudo apt install galen
```

### DNF

Add the Galen nightly repository:

```sh
sudo tee /etc/yum.repos.d/galen.repo << 'EOF'
[galen-nightly]
name=Galen Nightly Repository
baseurl=https://packages.ironclad-software.com/nightly/dnf/
enabled=1
gpgcheck=1
gpgkey=https://packages.ironclad-software.com/packages.gpg
EOF
```

Install Galen:

```sh
sudo dnf install galen
```

## Quick Start

Galen uses a local malware hash database and a precompiled YARA rules cache.

To update the local Malware Bazaar-derived signature database, first provide a Malware Bazaar API key:

```sh
export GALEN_AUTH_KEY="your-api-key"
galen update
```

Galen limits Malware Bazaar requests to one per 60 minutes in accordance with the Fair Use policy. Requests attempted during the
cooldown are skipped with the next permitted request time displayed; other update work continues.

Scan a directory:

```sh
galen scan ./some_directory
```

Emit a machine-readable JSON report:

```sh
galen scan ./some_directory --output json
```

For an initial evaluation, run Galen as an unprivileged user against a small, isolated test directory rather than scanning an entire production system.

Inert files such as EICAR and AMTSO test samples can be used to validate basic detection behaviour without handling live malware.

YARA rules can be added to a `yara/` directory in galen's installation location. YARA Forge's core ruleset is a good starting point. Note that the `galen update` command must be run before any YARA rules will be used.

## Configuration

Every scan and update setting can be set four ways, applied with this precedence:

1. CLI flags (highest priority)
2. Environment variables
3. Config file
4. Built-in defaults (lowest priority)

A setting not provided at a higher layer falls through to the next one, so a config file can set defaults for a whole host while a single invocation still overrides individual flags.

### Config file

By default Galen looks for `./galen.toml` (silently skipping it if absent). Point at a different file with `--config <path>` or the `GALEN_CONFIG` environment variable - either of those makes the file required, so a missing explicit path is an error rather than a silent no-op.

```toml
[scan]
database = "/var/lib/galen/signatures.sqlite"
yara_cache = "/var/lib/galen/yara/galen.yaraxc"
output = "json"
max_archive_depth = 5
max_archive_entries = 10000
max_decompressed_file_size_bytes = 67108864
max_file_size_bytes = 67108864
retained_entry_buffer_limit_bytes = 4194304
yara_scan_timeout_seconds = 10

[update]
database = "/var/lib/galen/signatures.sqlite"
yara_dir = "/var/lib/galen/yara/"
yara_cache = "/var/lib/galen/yara/galen.yaraxc"
```

Both tables are optional, as is every key within them. Unknown keys are rejected rather than silently ignored.

### Environment variables

| Variable | Applies to | Equivalent flag |
| --- | --- | --- |
| `GALEN_CONFIG` | scan, update | `--config` |
| `GALEN_DATABASE` | scan, update | `--database` / `-d` |
| `GALEN_YARA_CACHE` | scan, update | `--yara-cache` / `-y` |
| `GALEN_YARA_DIR` | update | `--yara-dir` |
| `GALEN_OUTPUT` | scan | `--output` / `-o` |
| `GALEN_MAX_ARCHIVE_DEPTH` | scan | `--max-archive-depth` |
| `GALEN_MAX_ARCHIVE_ENTRIES` | scan | `--max-archive-entries` |
| `GALEN_MAX_DECOMPRESSED_FILE_SIZE_BYTES` | scan | `--max-decompressed-file-size-bytes` |
| `GALEN_MAX_FILE_SIZE_BYTES` | scan | `--max-file-size-bytes` |
| `GALEN_RETAINED_ENTRY_BUFFER_LIMIT_BYTES` | scan | `--retained-entry-buffer-limit-bytes` |
| `GALEN_YARA_SCAN_TIMEOUT_SECONDS` | scan | `--yara-scan-timeout-seconds` |

`GALEN_AUTH_KEY` (the Malware Bazaar API key) is deliberately not part of this layering and cannot be set via a config file or a CLI flag - it stays environment-variable-only so a secret is never expected to live in a file that might be world-readable or accidentally committed.

## Current Status

Galen is currently in alpha.

The primary scanning, archive inspection, reporting, package distribution, and update pipelines are implemented. Current work is focused on resilience, calibration, configuration, and documentation ahead of the first stable release.

### Scanning

Implemented scanning features include:

* Recursive file and directory scanning
* Local SHA-256 hash matching
* Malware Bazaar-derived signature database updates
* Memory-efficient signature lookup using a sorted flat vector and binary search
* YARA scanning using a precompiled rules cache
* Conservative heuristic scoring
* Explicit verdicts and findings
* Magic-byte archive detection
* File and archive skip reasons

### Filesystem object handling

Galen is a static scanner for regular files and directories. It uses symlink-aware metadata checks so that directory traversal decisions are based on the path entry itself, not on a symlink target.

Current filesystem behaviour is:

* Symbolic links are not followed. Symlinked files and directories are skipped and reported with the `file_is_symlink` skip reason.
* Permission-denied files, directories, directory entries, and metadata lookups are skipped and reported with the `permission_denied` skip reason.
* Sockets, FIFOs, block devices, and character devices are not scanned as file content.
* If a socket, FIFO, block device, character device, or other non-file object is supplied as the top-level scan target, Galen reports an operational error because the requested target could not be scanned as a file or directory.
* If those non-file objects are encountered while recursively scanning a directory, they are ignored and not opened.
* Galen does not intentionally traverse outside a requested scan root. Directory recursion only follows real directories discovered under the selected root, and symlinks are skipped rather than followed.
* An explicitly supplied path is treated as a scan root in its own right, even if it is outside another directory the user may also be scanning.
* Archive member paths are virtual display paths only. Galen does not extract archive contents to disk, and archive path components that would escape a virtual archive namespace are normalised before reporting.

### Archive inspection

Supported archive formats include:

* ZIP
* JAR
* TAR
* GZ
* TGZ

Archive handling includes:

* Recursive inspection of nested archives
* Virtual paths for files contained inside archives
* Recursion limits
* Decompressed-size limits
* Retained-entry limits
* Encrypted-entry handling
* Path normalisation
* Explicit reporting when content is skipped

Galen can represent nested archive paths such as:

```text
./test_files/archive.zip!/nested.tar.gz!/sample.bin
```

This makes it possible to distinguish detections originating from filesystem files, archive entries, and archive containers.

#### Default scan limits

Galen's defaults are intended to scan ordinary software packages and documents while placing finite bounds on work triggered by unusually large files, deeply nested archives, and decompression bombs. They are conservative starting points rather than a guarantee that every hostile input is safe on every machine. Systems with unusually little memory, strict latency requirements, or trusted large artifacts may need tighter or looser values.

| Limit | Default | Why this is a sensible starting point |
| --- | ---: | --- |
| Archive depth | 5 levels | Handles common nested packaging, such as a compressed TAR containing another archive, without allowing an attacker to create an effectively unbounded recursive chain. |
| Archive entries | 10,000 per top-level archive tree | Accommodates sizeable application archives while bounding parser work and metadata overhead. The count is cumulative across nested archives, so splitting entries among child archives does not bypass it. |
| Filesystem file size | 64 MiB | Covers most executables, scripts, documents, and package members while avoiding hashing and YARA scanning arbitrarily large files. YARA uses this same ceiling so the scanner does not apply two conflicting definitions of an acceptable file size. |
| Decompressed file size | 64 MiB per entry | Allows typical expanded files but stops a small compressed member from expanding into an unbounded in-memory buffer. This limit applies independently of the compressed container size. |
| Retained archive-entry buffer | 4 MiB | Small allocations are reused to reduce allocator churn. Buffers that grow beyond 4 MiB are released after the entry is scanned so one large member does not permanently raise memory use for the remainder of the archive. This is a retention threshold, not a scan-size limit. |
| YARA timeout | 10 seconds per scan | Gives complex rules reasonable time on accepted files while bounding pathological rule or input combinations. The timeout applies to each YARA operation, not the entire directory scan. |

These limits can be changed with the corresponding `galen scan` options shown by `galen --help`. When a size or archive threshold is reached, Galen records an explicit skip reason in human and JSON reports.

The ZIP EOCD and ZIP64 locator sizes stored in `ScanConfig` use values defined by the ZIP format (22 bytes, a maximum 65,535-byte comment, and a 20-byte ZIP64 locator). They bound the footer search and are not exposed as CLI policy controls because changing them can make valid ZIP parsing unreliable.

### Reporting and automation

Galen currently provides:

* Human-readable scan summaries
* Versioned JSON scan reports
* Detection records with paths, scores, verdicts, surfaces, and findings
* Separate counts for filesystem files and archive entries
* Archive and skip statistics
* Scan timing
* Defined command exit codes
* A published JSON Schema for report version 1

### Distribution and supply chain

Current release infrastructure includes:

* Nightly APT packages
* Nightly DNF packages
* Alpha-tagged release builds
* Cryptographic release checksums
* CycloneDX software bills of materials
* SLSA provenance
* Verified project commits
* Automated dependency advisory checks

Stable packages and stable release channels are not yet available.

## Example Output

```text
galen v0.1.0
Loading "./signature_database.sqlite" signature database...
1101016 signatures loaded
Loading "./yara/compiled/galen.yaraxc" YARA rules cache...
5122 rules loaded
Starting scan...

Scanned 346 files
Skipped 3 files
  maximum recursion reached 2
  maximum decompressed size reached 1
2 known hash detections
3 YARA rules triggered
  GALEN_Test_AMTSO_PotentiallyUnwanted_Application: 1 files
  GALEN_Test_EICAR_Dropper_Or_Downloader: 2 files
  TRELLIX_ARC_Malw_Eicar: 11 files

----------- SCAN SUMMARY -----------
Scanned 346 files
  filesystem files: 46
  archive entries: 300
Scanned archives: 42
Skipped 3 files
  maximum recursion reached: 2
  maximum decompressed size reached: 1
Detection records: 14
  filesystem file: 2
  archive entry: 12
Scan time: 69.601612ms
```

## Exit Codes

Galen uses the following exit-code model:

```text
0 = scan completed, no detections
1 = scan completed, detections found
2 = scan failed or encountered an operational error
```

A detection is not treated as a scanner failure. Operational failures are reported separately so that scripts and CI jobs can distinguish between a completed scan and a scan that could not be trusted to finish correctly.

## JSON Output

JSON output can be requested with:

```sh
galen scan ./some_directory --output json
```

The report includes a `schema_version` and `status`.

Version 1 is documented by:

```text
schemas/scan-report-v1.schema.json
```

Representative success and error output is pinned by golden fixtures in
`tests/fixtures/json`. Tests compare the complete JSON written to stdout, so an
intentional output change must update the schema version and fixtures together.
Pull-request CI also validates those fixtures against the version of the v1
schema on the target branch, preventing accidental breaking changes to the
published machine-readable contract.

A successfully completed scan uses:

```json
{
  "schema_version": 1,
  "status": "ok"
}
```

A failed scan uses:

```json
{
  "schema_version": 1,
  "status": "error",
  "error": {
    "kind": "error_kind",
    "message": "human-readable description"
  }
}
```

The versioned schema is intended to support:

* Corpus regression testing
* CI integration
* Dashboards
* Automation
* Performance comparisons
* Detection-quality analysis

## Detection Sources

### Malware Bazaar hashes

Galen can maintain a local SQLite database of hashes obtained from Malware Bazaar.

SHA-256 is used as the primary lookup key. At scan startup, hashes are loaded into a sorted flat vector and queried using binary search.

This provides predictable memory use without the overhead of a large in-memory hash table.

Galen does not ship the Malware Bazaar database. Users retrieve it through the update command and remain responsible for complying with the upstream service's terms.

### YARA rules

Galen scans files using YARA-X and a precompiled rules cache.

The current development setup uses YARA Forge Core rules together with a small set of local rules for inert EICAR, AMTSO, and Fortinet test files.

Galen does not ship a production malware-rule collection. Users may provide their own rules or retrieve compatible third-party rule collections separately.

Third-party rules remain subject to their original licences and terms.

### Heuristics

Galen includes a lightweight scoring model that converts findings into verdicts:

* `Clean`
* `Informational`
* `Suspicious`
* `LikelyMalicious`
* `Malicious`

Findings can include known hashes, YARA matches, persistence-related indicators, packer-related indicators, and other statically observable characteristics.

The heuristic layer is intentionally conservative. It is intended to improve signal quality and explainability rather than act as an opaque machine-learning classifier.

Detection thresholds and confidence calibration remain under active development.

## Design Goals

### Predictable resource use

Security tooling should not destabilise the system it is intended to protect.

Galen aims to keep memory consumption and scanning behaviour bounded and understandable.

Current design choices include:

* Sorted-vector lookup instead of a large `HashSet`
* Precompiled YARA rules
* No memory-mapped scanning by default
* Reused and fixed-size buffers
* Bounded findings per file
* File-size and archive limits
* Archive-recursion limits
* Decompressed-data limits
* Explicit skip reasons

### Clear operator output

A scanner should make it clear:

* What was scanned
* What was skipped
* Why content was skipped
* Which rule or indicator triggered
* How a verdict was reached
* Whether a detection came from a file, archive entry, or archive container
* Whether the scan completed successfully

Galen favours explicit records over a single unexplained threat count.

### Conservative archive handling

Archive inspection is useful but creates a large hostile-input surface.

Galen treats archive readers as bounded parsers and applies limits before recursively scanning retained content. When a limit is reached, the content is reported as skipped rather than silently ignored.

Current regression coverage includes:

* Nested archives
* Mixed archive chains
* ZIP-inside-TAR.GZ archives
* TAR.GZ-inside-ZIP archives
* Archive recursion limits
* Decompression limits
* Archive-bomb-style inputs
* Path traversal names
* Encrypted entries
* Empty files and entries

Additional malformed-input testing and fuzzing are still required.

### Inspectable implementation

Galen favours small, explicit components and predictable control flow over complex detection abstractions.

The project is intended to remain approachable enough that users can inspect:

* How signatures are loaded
* How files are selected for scanning
* Which limits are applied
* How archive entries are retained
* How findings become verdicts
* How scan reports are generated

## Testing and Build Assurance

Galen has a stricter test and release pipeline than its alpha status might initially suggest. That pipeline reduces avoidable engineering risk, but it is not a substitute for years of real-world deployment or malware evaluation.

Current testing includes:

* Unit tests
* Regression tests
* Integration tests
* A generated scan corpus
* Nested-archive tests
* Archive-limit tests
* Malicious archive tests
* Path-handling tests
* Detection-report tests
* Mutation testing
* Nightly ZIP, TAR, and GZIP fuzzing
* Nightly live-sample testing against Malware Bazaar
* Code coverage measurement
* False-positive testing against Debian
* False-positive testing against Fedora
* False-positive testing against Arch Linux

ZIP, TAR, and GZIP archive parsers are fuzzed in parallel during nightly builds. Each target receives both raw malformed bytes and generated valid containers, uses strict scan limits, and runs for five minutes. Fuzz findings do not block nightly package publication; logs and reproducing inputs are retained as workflow artifacts for investigation. Surviving mutants are also being reviewed and documented where they expose meaningful gaps or deliberate equivalences.

The EICAR and AMTSO fixtures under `test_files/` are inert stand-ins; they say nothing about how galen handles a real, currently-circulating threat. Nightly builds also download a small batch (up to 15) of real, live malware samples from Malware Bazaar (`scripts/live-samples/`), scan them after a fresh signature update, and report how many were flagged malicious. Samples are downloaded to the runner's temporary directory, never committed or written into the working tree, and deleted before the job ends regardless of outcome - only hashes, families, and verdicts leave the runner, in an uploaded build artifact and the job summary. This job is observability-only for now (a Malware Bazaar hiccup or fair-use limit can cause an unrelated flake); it does not gate nightly package publication.

CI and release builds perform checks including:

* Rust formatting
* Clippy
* Unit and integration tests
* Regression tests
* RustSec advisory checks
* Release compilation
* A blocking mutation-score ratchet
* CycloneDX SBOM generation
* Checksumming
* SLSA provenance generation

Security advisory failures are treated as release blockers.

Mutation testing is also blocking in normal CI. The checked-in ratchet requires at least an 84.5% score and permits at most one timed-out mutant. Caught, missed, and timed-out mutants are included in the score denominator; mutants that cannot compile are excluded. The threshold should only move upwards as surviving mutants are eliminated or documented, preventing later changes from silently giving back mutation coverage.

Unit-test coverage has a separate blocking ratchet measured with cargo-tarpaulin. CI currently requires at least 81.5% line coverage and uploads the HTML and JSON reports for inspection. As with mutation testing, this floor should only move upwards so new changes cannot silently trade away established test coverage.

Archive fuzz targets require nightly Rust and `cargo-fuzz`. Build all targets locally with:

```sh
cargo +nightly fuzz build
```

Run a short smoke test or a longer local session with:

```sh
cargo +nightly fuzz run fuzz_zip -- -runs=100
cargo +nightly fuzz run fuzz_tar
cargo +nightly fuzz run fuzz_gzip
```

Reproduce a CI finding by downloading its artifact and passing the crash input to the corresponding target:

```sh
cargo +nightly fuzz run fuzz_zip fuzz/artifacts/fuzz_zip/crash-<hash>
```

Normal CI artifacts are development snapshots and are not releases. Tagged alpha releases use versions such as:

```text
v0.1.0-alpha.1
```

These measures provide build assurance and traceability. They are not a claim that Galen is production-hardened.

## Benchmarks

The following results come from development runs performed on the same machine.

They are early engineering measurements, not formal independent performance claims.

| Scanner |         Mode |   Files | Wall time |  Max RSS | Minor page faults | Involuntary context switches |
| ------- | -----------: | ------: | --------: | -------: | ----------------: | ---------------------------: |
| Galen   |    Hash only |   ~300k |    2m 07s |   ~43 MB |             4,026 |                            0 |
| Galen   | YARA enabled |   ~355k |   12m 28s |  ~187 MB |            78,072 |                       19,939 |
| ClamAV  |    Recursive |   ~300k |   72m 45s | ~1.19 GB |        60,728,859 |                      225,140 |

These numbers came from a one-off manual run and are not reproducible as published. An automated version of this comparison now runs nightly (`.github/workflows/nightly.yaml`, job `benchmark-clamav`) against a smaller, pinned, reproducible corpus (`scripts/bench/`), and its results are uploaded as a build artifact rather than gating the build. Treat the table above as historical context until it is refreshed from that job's output.

This comparison is not intended as criticism of ClamAV.

ClamAV is a mature, widely deployed, production-grade scanner with a substantially broader feature set, larger detection database, wider format support, and many years of operational hardening.

Galen is a much younger tool making different engineering trade-offs.

The useful conclusion is deliberately narrow:

> Galen is already fast and resource-conscious enough to justify further evaluation as a lightweight local scanner, while still having substantial correctness, assurance, and detection-depth work ahead of it.

## Current Limitations

Galen is not currently a production replacement for ClamAV or a commercial endpoint security platform.

Known limitations include:

* Limited evaluation against representative live-malware collections
* No independent detection-effectiveness evaluation
* Detection thresholds are still being calibrated
* Archive and parser fuzzing is not yet complete
* Configuration support is limited
* YARA rule updates are not yet fully automated
* No stable APT, DNF, RPM, DEB, or AUR release channel
* No real-time or on-access scanning
* No background daemon mode
* No dynamic analysis
* No sandboxing
* Limited executable-format analysis
* No guarantee of detecting current malware families
* Limited operational experience outside development and test environments

The absence of a detection does not prove that a file is safe.

## Trying Galen Safely

Galen may inspect files and archives that are intentionally malicious, malformed, or designed to exhaust parser resources.

When evaluating it:

* Run Galen as an unprivileged user where possible
* Start with small, isolated test directories
* Do not begin by scanning production-critical systems
* Prefer EICAR, AMTSO, and other inert test files for initial validation
* Do not manually extract unknown malware samples
* Do not execute anything discovered during a scan
* Keep real-malware handling inside a purpose-built isolated laboratory
* Treat live-malware testing as a separate operational discipline

Galen's archive limits reduce risk but do not make arbitrary hostile files safe.

## Reporting Feedback

Reports from different distributions, filesystems, hardware configurations, and workloads are welcome.

A useful issue report should include:

* Galen version
* Linux distribution and version
* Installation method
* Command used
* Expected behaviour
* Actual behaviour
* Relevant human-readable or JSON output
* Approximate file count and data volume
* Performance measurements, where relevant
* A minimal inert reproducer, where possible

Please redact personal paths, usernames, API keys, and other sensitive information.

Do not attach live malware to GitHub issues. For detection-related reports, provide a cryptographic hash, public source reference, or safely constructed inert reproducer where appropriate.

Particularly useful feedback includes:

* False positives on clean Linux packages
* False negatives involving recognised inert test files
* Confusing verdicts or findings
* Incorrect exit codes
* JSON schema inconsistencies
* Archive recursion or limit errors
* Malformed archives that cause crashes
* Excessive CPU or memory use
* Packaging and repository problems
* Behaviour differences across distributions

## Planned Work

### Before the first stable release

Current priorities include:

* Complete initial fuzzing coverage
* Document surviving mutants
* Add configurable scan and archive limits
* Improve operator documentation
* Improve detection-confidence calibration
* Stabilise package and release workflows

### Later work

Longer-term work may include:

* Configuration-file support
* Environment-variable configuration
* YARA Forge update support
* File entropy analysis
* Executable-format classification
* ELF analysis
* Additional archive formats
* Parallel scanning experiments
* Systemd service mode
* A dedicated non-root service user
* Real-time or on-access monitoring
* Broader malicious and clean corpus evaluation
* Stable DEB, RPM, APT, DNF, and AUR distribution

## Minimum Supported Rust Version

Galen currently requires Rust 1.95.0 or newer.

The required version is declared through the package's `rust-version` metadata and should be treated as the project's current minimum supported Rust version.

The MSRV may change before the first stable release as the implementation and dependency set evolve.

## Project Philosophy

Galen is not trying to be a ClamAV clone.

It explores what a smaller Rust-based Linux scanner can look like when built around:

* Predictable memory use
* Explicit safety limits
* Clear operator output
* Testable scan reports
* Conservative archive handling
* Strong build traceability
* Simple, inspectable design

ClamAV remains the sensible default recommendation for most Linux users who need a mature and widely deployed malware scanner today.

Galen is building towards a smaller and easier-to-reason-about alternative, while remaining explicit about the testing, detection coverage, and operational experience it has not yet accumulated.

## Licence

Galen is licensed under the GNU General Public License version 3.0 or later.

Galen is free and open-source security tooling. You may use, study, modify, and redistribute it under the terms of GPLv3 or any later version.

Galen does not ship malware signatures, third-party YARA collections, or third-party detection feeds for production use.

The included local YARA rules are limited to inert EICAR, AMTSO, and Fortinet test cases. Users may supply their own signatures or use Galen's updater commands to retrieve material from third-party sources.

Third-party rules, databases, signatures, and feeds remain subject to their own licences and terms.

## Disclaimer

Galen is pre-1.0 security software and has not yet been independently evaluated or battle-tested against a representative live-malware corpus.

It may miss malicious files. It may produce false positives. It may behave incorrectly when processing malformed or adversarial inputs.

Do not rely on Galen as your only security control.
