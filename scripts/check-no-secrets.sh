#!/usr/bin/env bash
# Fail when the git index holds anything that must never be tracked: key material,
# and build outputs that are not secret but are not sources either -- zero-knowledge
# proving artefacts and exported models.
#
# Usage:
#   scripts/check-no-secrets.sh              scan the repository that contains this script
#   scripts/check-no-secrets.sh --self-test  prove the scanner catches planted secrets
#
# The scan reads blobs from the index (`git ls-files` + `git cat-file`), not the
# working tree, so an unstaged local file cannot hide or fake a finding.
#
# Findings:
#   path     a tracked path that must never exist:
#            *-keypair.json, *.keypair.json, swarm.key, *.key, *.pem, *.p12, *.pfx,
#            id_rsa*, id_ed25519*, *.log, runtime/**, solana/deploy/**,
#            .env and .env.* (except .env.example)
#   content  a tracked blob that contains a Solana secret key (a JSON array of
#            exactly 64 integers in 0..255, in any file type), a PEM private-key
#            block with its body, or an IPFS private-network swarm key
set -euo pipefail

SELF_TEST_TMP=""

cleanup_self_test() {
  if [ -n "${SELF_TEST_TMP}" ]; then
    rm -rf "${SELF_TEST_TMP}"
  fi
}

self_test() {
  SELF_TEST_TMP="$(mktemp -d)"
  trap cleanup_self_test EXIT
  local repo="${SELF_TEST_TMP}/repo"
  mkdir -p "${repo}"
  git -C "${repo}" init -q
  git -C "${repo}" config user.email check@example.invalid
  git -C "${repo}" config user.name check
  git -C "${repo}" config commit.gpgsign false

  # 1. A clean repository passes.
  mkdir -p "${repo}/docs"
  printf '# clean\n' > "${repo}/docs/README.md"
  printf '{"name":"ok","values":[1,2,3]}\n' > "${repo}/docs/config.json"
  printf 'EXAMPLE=1\n' > "${repo}/.env.example"
  git -C "${repo}" add -A && git -C "${repo}" commit -q -m clean
  if ! scan "${repo}" >/dev/null; then
    echo "self-test FAILED: clean repository was rejected" >&2
    return 1
  fi

  # 2. Each planted secret is caught, by path or by content.
  local fake_key
  fake_key="[$(seq -s, 1 64)]"
  mkdir -p "${repo}/solana/deploy" "${repo}/runtime/protocol" "${repo}/docker/ipfs" "${repo}/notes"
  printf '%s\n' "${fake_key}" > "${repo}/solana/deploy/kswarm_protocol-keypair.json"
  printf '%s\n' "${fake_key}" > "${repo}/notes/looks-harmless.json"
  printf 'const k = %s;\n' "${fake_key}" > "${repo}/notes/embedded.mjs"
  printf '{"wallet":{"secretKey":%s}}\n' "${fake_key}" > "${repo}/notes/nested.json"
  printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(printf 'ab%.0s' $(seq 1 32))" > "${repo}/docker/ipfs/swarm.key"
  printf -- '-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n' "$(printf 'MIIB%.0s' $(seq 1 16))" > "${repo}/notes/server.txt"
  printf 'x\n' > "${repo}/runtime/protocol/admin.json"
  printf 'x\n' > "${repo}/notes/debug.log"
  printf 'SECRET=1\n' > "${repo}/.env"
  mkdir -p "${repo}/research/bench"
  printf 'x\n' > "${repo}/research/bench/circuit.pk"
  printf 'x\n' > "${repo}/research/bench/kzg.srs"
  printf 'x\n' > "${repo}/research/bench/model.onnx"
  git -C "${repo}" add -A -f && git -C "${repo}" commit -q -m planted
  local output
  if output="$(scan "${repo}" 2>&1)"; then
    echo "self-test FAILED: planted secrets were accepted" >&2
    return 1
  fi
  local expected
  for expected in \
    "path solana/deploy/kswarm_protocol-keypair.json" \
    "content notes/looks-harmless.json" \
    "content notes/embedded.mjs" \
    "content notes/nested.json" \
    "path docker/ipfs/swarm.key" \
    "content docker/ipfs/swarm.key" \
    "content notes/server.txt" \
    "path runtime/protocol/admin.json" \
    "path notes/debug.log" \
    "path .env" \
    "path research/bench/circuit.pk" \
    "path research/bench/kzg.srs" \
    "path research/bench/model.onnx"; do
    if ! grep -qF -- "${expected}" <<<"${output}"; then
      echo "self-test FAILED: missing finding '${expected}'" >&2
      echo "${output}" >&2
      return 1
    fi
  done
  echo "self-test OK: clean repository accepted, $(grep -c . <<<"${output}") findings reported for planted files"
}

scan() {
  local repo="$1"
  git -C "${repo}" rev-parse --show-toplevel >/dev/null
  python3 - "${repo}" <<'PY'
import json
import re
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import PurePosixPath

repo = sys.argv[1]

PATH_GLOBS = (
    "*-keypair.json",
    "*.keypair.json",
    "swarm.key",
    "*.key",
    "*.pem",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_ed25519*",
    "*.log",
    # Zero-knowledge proving artefacts and exported models. Proving and verifying
    # keys, structured reference strings and circuit parameters are build outputs;
    # an ONNX file is the model those artefacts were built for. None of them is a
    # secret -- an SRS is published so anyone can verify -- but none belongs in the
    # index either, and `.gitignore` alone does not stop `git add -f` or reach a file
    # that is already tracked.
    "*.pk",
    "*.vk",
    "*.srs",
    "*.zkey",
    "*.params",
    "*.onnx",
)
PATH_PREFIXES = ("runtime/", "solana/deploy/")
ENV_ALLOWED = {".env.example"}

KEY_ARRAY_RE = re.compile(rb"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]")
# Real keys span lines: a BEGIN line followed by base64, a PSK header followed by the
# encoding line and 64 hex digits. Source code that merely names the markers does not match.
PEM_RE = re.compile(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\r?\n[A-Za-z0-9+/=]{16,}")
PSK_RE = re.compile(rb"/key/swarm/psk/1\.0\.0/\r?\n/base16/\r?\n[0-9a-fA-F]{64}")


def forbidden_path(path: str) -> str | None:
    name = PurePosixPath(path).name
    lowered = name.lower()
    for prefix in PATH_PREFIXES:
        if path.startswith(prefix):
            return f"under {prefix}"
    for glob in PATH_GLOBS:
        if fnmatch(lowered, glob):
            return f"matches {glob}"
    if (name == ".env" or name.startswith(".env.")) and name not in ENV_ALLOWED:
        return "environment file"
    return None


def is_key_array(value) -> bool:
    return (
        isinstance(value, list)
        and len(value) == 64
        and all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value)
    )


def json_holds_key(value) -> bool:
    if is_key_array(value):
        return True
    if isinstance(value, dict):
        return any(json_holds_key(item) for item in value.values())
    if isinstance(value, list):
        return any(json_holds_key(item) for item in value)
    return False


def forbidden_content(path: str, blob: bytes) -> str | None:
    if PEM_RE.search(blob):
        return "PEM private key block"
    if PSK_RE.search(blob):
        return "IPFS private-network swarm key"
    match = KEY_ARRAY_RE.search(blob)
    if match and is_key_array(json.loads(match.group(0))):
        return "64-byte secret key array"
    if path.endswith(".json"):
        try:
            if json_holds_key(json.loads(blob)):
                return "64-byte secret key array"
        except ValueError:
            pass
    return None


listing = subprocess.run(
    ["git", "-C", repo, "ls-files", "-z", "--stage"], check=True, capture_output=True
).stdout
entries = []
for record in listing.split(b"\0"):
    if not record:
        continue
    meta, path = record.split(b"\t", 1)
    mode, sha, _stage = meta.split()
    if mode == b"160000":  # submodule pointer, no blob
        continue
    entries.append((sha.decode(), path.decode()))

findings = []
for sha, path in entries:
    reason = forbidden_path(path)
    if reason:
        findings.append(f"path {path}: {reason}")

batch = subprocess.run(
    ["git", "-C", repo, "cat-file", "--batch"],
    input="".join(f"{sha}\n" for sha, _ in entries).encode(),
    check=True,
    capture_output=True,
).stdout
offset = 0
for sha, path in entries:
    header_end = batch.index(b"\n", offset)
    header = batch[offset:header_end].decode().split()
    size = int(header[2])
    blob = batch[header_end + 1 : header_end + 1 + size]
    offset = header_end + 1 + size + 1
    reason = forbidden_content(path, blob)
    if reason:
        findings.append(f"content {path}: {reason}")

if findings:
    print(f"check-no-secrets: {len(findings)} finding(s) in the git index of {repo}", file=sys.stderr)
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    sys.exit(1)
print(f"check-no-secrets: OK, {len(entries)} tracked files, nothing untrackable in the index")
PY
}

main() {
  case "${1:-}" in
    --self-test)
      self_test
      ;;
    "")
      local root
      root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
      scan "${root}"
      ;;
    *)
      echo "usage: $0 [--self-test]" >&2
      exit 2
      ;;
  esac
}

main "$@"
