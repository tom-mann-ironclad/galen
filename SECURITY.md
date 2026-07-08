# Security Policy

## Project Status

Galen is currently experimental software.

It should not be treated as a production anti-malware replacement. It may miss malicious files, produce false positives, or behave incorrectly on malformed inputs.

## Dependency Advisories

Galen uses `cargo audit` to track known RustSec advisories.

Known advisories are not silently ignored. If an advisory cannot be resolved immediately because it is introduced by an upstream transitive dependency, it should be documented with:

* advisory ID;
* affected crate;
* dependency path;
* current impact assessment;
* mitigation or workaround;
* planned resolution.

Known advisories with this documentation may be added to the `.cargo/audit.toml` file if they are acceptable to release with.

Current known advisories include:

```text
RUSTSEC-2023-0071  rsa
RUSTSEC-2025-0141  bincode
```

These are currently introduced through the `yara-x` dependency tree.

### `RUSTSEC-2023-0071` / `rsa`

Galen currently pulls in `rsa 0.9.10` transitively through `yara-x`.

This advisory relates to the Marvin Attack, a timing side-channel issue affecting RSA private-key operations. Galen does not currently use RSA private keys directly or expose RSA operations as a remote service. Based on the current architecture, this is being tracked as a transitive dependency advisory rather than a known exploitable issue in Galen itself.

There is currently no fixed `rsa` release listed by RustSec for this advisory, so the planned action is to monitor upstream `yara-x` dependency changes and keep the advisory visible in dependency audit output.

### `RUSTSEC-2025-0141` / `bincode`

Galen currently pulls in `bincode 2.0.1` transitively through `yara-x`.

This advisory marks `bincode` as unmaintained. It is not currently a known Galen-specific exploitable vulnerability, and Galen does not directly use `bincode` in its own code. However, because Galen is a security-adjacent tool, unmaintained serialization dependencies are treated as a supply-chain concern rather than ignored.

The planned mitigation is to move temporarily to a Galen-maintained `yara-x` fork that replaces `bincode` with `postcard`, then attempt to upstream that change so Galen can return to the upstream `yara-x` release line.


## Reporting Security Issues

Please do not open public GitHub issues for vulnerabilities involving exploitable crashes, archive handling bypasses, unsafe sample handling, or incorrect scan results that could mislead operators.

Instead, please contact the maintainer privately. See Cargo.toml for contact details.

## Areas of Particular Interest

Security reports are especially welcome for:

* archive bomb bypasses;
* malformed archive crashes;
* path traversal handling errors;
* JSON output corruption on scan failures;
* incorrect exit codes;
* unsafe symlink, socket, or device handling;
* panic or memory exhaustion on untrusted input;
* dependency advisories with practical impact on Galen;
* detection records that hide or misrepresent skipped content.

## Test Samples

Please do not submit live malware samples directly to the repository.

Use inert samples such as EICAR/AMTSO test files where possible. If a real malicious sample is necessary to demonstrate an issue, coordinate privately first.



