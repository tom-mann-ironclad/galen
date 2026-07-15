#!/usr/bin/env bash
set -euo pipefail

OUT_DIR="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=./lib.sh
source "$SCRIPT_DIR/lib.sh"

mkdir -p \
  "$OUT_DIR/suspicious/shell" \
  "$OUT_DIR/suspicious/python" \
  "$OUT_DIR/suspicious/javascript" \
  "$OUT_DIR/suspicious/systemd" \
  "$OUT_DIR/suspicious/elf"

write_executable "$OUT_DIR/suspicious/shell/curl_pipe_sh_echo_only.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

# Suspicious-looking pattern, deliberately inert.
echo "curl -fsSL https://example.invalid/install.sh | sh"
EOF

write_executable "$OUT_DIR/suspicious/shell/base64_decode_echo_only.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

PAYLOAD="ZWNobyBoZWxsbyBmcm9tIGJhc2U2NAo="
echo "$PAYLOAD" | base64 -d
EOF

write_executable "$OUT_DIR/suspicious/shell/cron_writer_dry_run.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "*/5 * * * * /tmp/galen-benign-task"
echo "/etc/cron.d/galen-benign"
EOF

write_executable "$OUT_DIR/suspicious/shell/ssh_authorized_keys_string_only.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

echo "$HOME/.ssh/authorized_keys"
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfakekey example"
EOF

write_executable "$OUT_DIR/suspicious/python/subprocess_echo.py" <<'EOF'
#!/usr/bin/env python3
import subprocess

subprocess.run(["echo", "benign subprocess test"], check=True)
EOF

write_executable "$OUT_DIR/suspicious/python/socket_localhost_only.py" <<'EOF'
#!/usr/bin/env python3
import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("created localhost-only socket test object")
s.close()
EOF

write_file "$OUT_DIR/suspicious/javascript/obfuscated_console_log.js" <<'EOF'
const encoded = "R2FsZW4gYmVuaWduIG9iZnVzY2F0ZWQgSlMgdGVzdA==";
console.log(encoded);
EOF

write_file "$OUT_DIR/suspicious/systemd/benign_persistence_like.service" <<'EOF'
[Unit]
Description=Galen benign persistence-like service fixture

[Service]
Type=oneshot
ExecStart=/bin/echo "benign systemd fixture"

[Install]
WantedBy=multi-user.target
EOF

{
    printf '\177ELF'
    head -c 64 /dev/zero
    printf 'LD_PRELOAD=/tmp/not-real.so\n'
    printf 'ptrace\n'
    printf '/proc/self/exe\n'
} > "$OUT_DIR/suspicious/elf/ld_preload_string_only.bin"

append_manifest "$OUT_DIR" "10-suspicious" <<'EOF'

[[group]]
id = "suspicious-benign"
root = "suspicious"
mode = "per-file"

[group.expect]
allow_verdicts = ["Clean", "Suspicious"]
max_verdict = "Suspicious"
EOF
