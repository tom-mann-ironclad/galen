# Galen

Galen is an experimental Rust security intelligence and scanning pipeline for Linux.

It combines local hash-based detection, YARA rule scanning, archive inspection, and lightweight heuristics into a fast command-line scanner designed to be understandable, resource-conscious, and operator-friendly.

## Current Status

Galen is in early development.

Implemented so far:

* Local SHA-256 hash matching against a Malware Bazaar-derived SQLite database
* Signature database update command
* Memory-efficient in-memory signature lookup using a sorted flat vector and binary search
* YARA scanning using a precompiled rules cache
* Heuristic scoring and verdicts
* Recursive directory scanning
* ZIP/JAR archive scanning
* TAR, GZ, and TGZ archive scanning
* Archive recursion and decompression limits to reduce archive bomb risk
* Magic-byte archive detection
* File skip reasons
* Human-readable scan summaries
* JSON scan output
* Versioned JSON scan output schema
* Detection records including path, score, verdict, surface, and findings

Still in progress:

* Expanded regression and corpus tests
* Custom error types
* Configurable scan limits
* CI/CD
* Packaging - nightly releases are available via APT and DNF, but no stable releases or AUR support at this time.
* build assurance
* Broader clean and malicious corpus testing
* More mature operator documentation

The current goal is to make Galen predictable, testable, and safe to operate before adding more advanced detection features.

## Build assurance

Normal CI builds are treated as snapshot artifacts and are not releases.

Tagged releases are currently alpha-only and use tags such as `v0.1.0-alpha.1`. Release builds run formatting, Clippy, tests, RustSec advisory checks, release compilation, CycloneDX SBOM generation, checksumming, and SLSA provenance generation.

This is early build-assurance work and not a claim that Galen is production-hardened.

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

Galen tracks detections inside archives using virtual paths such as:

```text
./test_files/archive.zip!/nested.tar.gz!/sample.bin
```

This makes it easier to understand whether a detection came from a filesystem file, an archive entry, or the archive container itself.

## Installation

Only a `nightly` version of Galen is currently packaged. It is available on APT and DNF.

For APT users:

```
# 1. Create the keyrings directory if it doesn't exist
sudo mkdir -p /etc/apt/keyrings

# 2. Download the public key safely into that directory
sudo curl -fsSL https://packages.ironclad-software.com/packages.gpg -o /etc/apt/keyrings/galen.gpg

# 3. Add the repository configuration file, tightly scoped to that key
echo "deb [signed-by=/etc/apt/keyrings/galen.gpg] https://packages.ironclad-software.com/nightly/apt /" | sudo tee /etc/apt/sources.list.d/galen.list

# 4. Update and install
sudo apt update
sudo apt install galen
```

For DNF users:

Add the configuration for the repository:

```
sudo tee /etc/yum.repos.d/galen.repo << 'EOF'
[galen-nightly]
name=Galen Nightly Repository
baseurl=https://packages.ironclad-software.com/nightly/dnf/
enabled=1
gpgcheck=1
gpgkey=https://packages.ironclad-software.com/packages.gpg
EOF
```

Then install with `dnf install galen`.

## Design Goals

Galen is being built around a few practical goals:

### Low operational overhead

Security tools should not make the host unstable. Galen aims to keep memory usage predictable and avoid expensive defaults where possible.

Examples of current design choices:

* Minimal allocations and reused fixed-size buffers to reduce memory overhead
* Sorted vector lookup instead of a large `HashSet` for malware hashes
* YARA precompiled rule cache
* No memory-mapped scanning by default
* File size and archive safety limits
* Bounded findings per file
* Explicit skip reasons

### Clear operator output

A scanner should make it clear what happened:

* What was scanned
* What was skipped
* Why something was skipped
* What triggered a detection
* Whether the detection came from a normal file, archive entry, or archive container
* Whether the scan completed successfully

The JSON output is intended for future corpus tests, CI regression checks, dashboards, and automation.

### Conservative archive handling

Archive support is useful, but dangerous if implemented carelessly. Galen currently applies limits around archive recursion and decompressed data size, and records skipped files rather than silently ignoring them.

Archive formats currently supported:

* ZIP
* TAR
* GZ
* TGZ
* JAR

Additional regression testing is planned for:

* Zip bombs
* Nested archives
* Malformed archives
* Encrypted archives
* Path traversal names
* Mixed archive chains such as ZIP inside TAR.GZ and TAR.GZ inside ZIP

## Detection Sources

Galen currently supports:

### Malware Bazaar hashes

Galen can update a local SQLite database with hashes from Malware Bazaar and load them into memory for fast local matching.

The local database currently uses SHA-256 hashes as the primary lookup key.

> Note that the GALEN_AUTH_KEY will need to be set with an API key from Malware Bazaar to use the `update` command.

### YARA rules

Galen supports YARA scanning through a precompiled YARA and YARA-X rules cache.

The current development setup uses YARA Forge Core rules, along with a small number of local test rules for EICAR/AMTSO-style test cases.

### Heuristics

Galen includes a simple scoring model which maps findings into verdicts such as:

* `Clean`
* `Informational`
* `Suspicious`
* `LikelyMalicious`
* `Malicious`

The heuristic layer is intentionally conservative and still under active development.

## Benchmarks

The following benchmarks are from development runs on the same machine and should be treated as early engineering measurements, not formal independent performance claims.

They are included to show where Galen currently sits and what trade-offs are being made.

| Scanner | Mode | Files | Wall time | Max RSS | Minor page faults | Involuntary context switches |
|---|---:|---:|---:|---:|---:|---:|
| Galen | hash-only | ~300k | 2m 07s | ~43 MB | 4,026 | 0 |
| Galen | YARA enabled | ~355k | 12m 28s | ~187 MB | 78,072 | 19,939 |
| ClamAV | recursive | 300,981 | 72m 45s | ~1.19 GB | 60,728,859 | 225,140 |

This comparison is not intended as a criticism of ClamAV.

ClamAV is a mature, widely deployed, production-grade scanner with a much larger signature database, many years of hardening, and broader format support. Galen is a young project with a smaller feature set and a different set of engineering trade-offs.

The useful takeaway is narrower:

> Galen is already in a performance range that makes it interesting as a lightweight local scanner, while still leaving a lot of correctness, assurance, and detection-depth work to do.

## Current Limitations

Galen should not currently be treated as a production anti-malware replacement.

Known limitations include:

* Test coverage is still incomplete (~81.4% code coverage with a ~76.4% mutation coverage)
* JSON schema versioning is not fully documented yet
* Configuration support is still limited
* No packaged `.deb` or `.rpm` release yet (although nightly is available)
* Limited CI/CD pipeline
* Detection quality is still being calibrated
* Archive handling needs more regression tests
* YARA rule update support is not complete
* No real-time/on-access scanning yet
* No dynamic analysis or sandboxing
* No guarantee of detecting current malware families

Galen is best understood today as an experimental static scanner and security engineering project.

## Planned Work

Near-term priorities:

* Increase unit test, mutation test and regression test coverage
* Add a corpus test runner using JSON output
* Define and document JSON schema versioning
* Add custom error types
* Make invalid CLI arguments fail closed
* Ensure JSON mode always emits valid JSON, including on scan failures
* Align exit codes between human and JSON output
* Add configurable scan limits
* Add regression tests for archive edge cases
* Improve CI with additional testing, cross compilation, benchmarking and code security steps

Later priorities:

* Config file and environment variable support
* Systemd service mode with a dedicated non-root user
* YARA Forge update support
* File entropy checks
* Executable format classification
* ELF analysis
* Additional confidence calibration against clean, suspicious, and malicious corpora
* `.deb` and `.rpm` packaging
* Performance experiments with parallel scanning

## Example Usage

Update the local signature database:

```sh
galen update
```

Scan a path:

```sh
galen scan ./some_directory
```

Emit JSON output:

```sh
galen scan ./some_directory --output json
```

The JSON scan output includes `schema_version` and `status`. Version `1` is
documented by [`schemas/scan-report-v1.schema.json`](schemas/scan-report-v1.schema.json).
A completed scan uses `status: "ok"` and includes the scan summary. A failed scan
uses `status: "error"` and includes an `error` object with `kind` and `message`.

Exit codes are intended to follow this model:

```text
0 = scan completed, no detections
1 = scan completed, detections found
2 = scan failed or encountered an operational error
```

This behaviour is still being hardened and aligned across output modes.

## Safety Notes

Galen may inspect archives and files that are intentionally malicious or malformed.

When testing:

* Use isolated test directories
* Do not run unknown samples on production systems
* Do not extract malware samples manually unless you know what you are doing
* Prefer inert test files such as EICAR/AMTSO samples for basic validation
* Treat real malware handling as a separate operational discipline

## Minimum Supported Rust Version

Galen currently requires Rust 1.95 or newer.

This is because Galen uses the Rust 2024 edition, which was stabilized in Rust 1.95.0.

## Project Philosophy

Galen is not trying to be a ClamAV clone.

The project is mainly about exploring what a small, understandable, Rust-based Linux scanner can look like when built with:

* predictable memory usage;
* explicit safety limits;
* clear operator output;
* testable scan reports;
* cautious archive handling;
* and a bias toward simple, inspectable design.

ClamAV remains the sensible default recommendation for most Linux users who need a mature anti-malware scanner today.

Galen is an experiment in building something smaller, newer, and easier to reason about.

## License

Galen is licensed under the GNU General Public License v3.0 or later.

Galen is free and open-source software security tooling. You may use, study, modify, and redistribute it under the terms of the GPLv3 or any later version.

Galen does not ship malware signatures, YARA rules, or third-party detection feeds for 'production use'. The only included YARA rules are for EICAR and Fortinet test files. Users may provide their own rules/signatures or use Galen's updater commands to retrieve content from third-party sources. Those rules, signatures, databases, and feeds remain under their own upstream licences and terms.

## Disclaimer

Galen is experimental software.

It may miss malicious files. It may produce false positives. It may behave incorrectly on malformed inputs. Do not rely on it as your only security control.
