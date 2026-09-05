#!/usr/bin/env bash
# Fail when the git index holds a file whose path, or whose contents, match one of
# the shapes listed below: key material in the forms this project produces, and
# build outputs that are not secret but are not sources either -- zero-knowledge
# proving artefacts and exported models.
#
# Usage:
#   scripts/check-no-secrets.sh              scan the repository that contains this script
#   scripts/check-no-secrets.sh --self-test  prove the scanner catches planted files
#
# What this covers, and what it does not. It reads blobs from the index of this
# checkout (`git ls-files` + `git cat-file`), so an unstaged local file cannot
# hide or fake a finding -- and so a file that was committed and later deleted is
# invisible to it. It does not read history, and it does not detect "secrets" in
# general. It detects exactly the shapes enumerated below. A credential in a form
# that is not one of them -- an API token, a password, a cloud key id, a private
# key in a format not listed -- passes this check, and passing it is not evidence
# that a tree holds no secret.
#
# Findings:
#   path     a tracked path that must never exist:
#            *-keypair.json, *.keypair.json, swarm.key, *.key, *.pem, *.p12, *.pfx,
#            id_rsa*, id_ed25519*, *.log, runtime/**, solana/deploy/**,
#            .env and .env.* (except .env.example)
#   content  a tracked blob that contains one of:
#            * a Solana secret key as a JSON array of exactly 64 integers in
#              0..255, in any file type -- what `solana-keygen` writes;
#            * the same key base58-encoded, which is the form a wallet exports
#              and a person pastes: 85 to 90 base58 characters that decode to 64
#              bytes whose last 32 are the ed25519 public key of the first 32.
#              That relation, and not the length, is what identifies it. Solana
#              *public* keys decode to 32 bytes and are legitimately everywhere
#              in this tree; transaction signatures decode to 64 bytes and are
#              committed in docs/, and they fail the relation;
#            * a PEM private-key block with its body;
#            * an IPFS private-network swarm key
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

  # 1. A clean repository passes -- including the base58 strings that are
  #    legitimately tracked and that a rule keyed on length alone would flag.
  #    Solana public keys are 32 bytes and 43 or 44 base58 characters. Transaction
  #    signatures are 64 bytes and 87 or 88, which is a keypair export exactly.
  #
  #    Counted over maximal base58 runs in every tracked blob, at 840e1054, the
  #    commit this branch sits on, with N as the run length:
  #
  #      git ls-files -z | xargs -0 grep -haoP \
  #        '(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{N}(?![1-9A-HJ-NP-Za-km-z])' \
  #        | wc -l
  #
  #      N=43  122        N=87   7
  #      N=44  296        N=88  10
  #
  #    All 17 of the 87- and 88-character runs decode to exactly 64 bytes, and 7 of
  #    them are in a single phase-0 findings record that the kswarm export publishes.
  #    (Naming that file here is what the publish doc-reference gate refuses: it is
  #    not part of the kswarm-protocol export, and this script is.)
  #    At this branch's head the same command returns 123, 297, 8
  #    and 11: the difference is the four fixtures planted below, one run of each
  #    length.
  #
  #    Recount with that command and not with \b. 0, O, I and l are word characters
  #    and are not base58 characters, so a run sitting beside one of them is not at a
  #    word boundary and is skipped: \b[1-9A-HJ-NP-Za-km-z]{43}\b returns 15 here and
  #    16 at this branch's head, against 122 and 123 for the run form, and {44}
  #    returns 197 and 198 against 296 and 297.
  #
  #    An all-ones string in cli/tests/vectors/aggregate_journal_vectors.json decodes
  #    to 64 zero bytes. Only the ed25519 relation separates a real export from any of
  #    these, and the five lines below are what prove it does.
  mkdir -p "${repo}/docs"
  printf '# clean\n' > "${repo}/docs/README.md"
  printf '{"name":"ok","values":[1,2,3]}\n' > "${repo}/docs/config.json"
  printf 'EXAMPLE=1\n' > "${repo}/.env.example"
  cat > "${repo}/docs/addresses.md" <<'ADDRESSES'
public key, 44 characters:  ERNzRcYhX6UYboXAAP7vwzbCKsULYu21R4RFNvDD8CkM
public key, 43 characters:  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
transaction signature, 88:  3uQhaK183jTnDWYSEQe5dLh2uakpqqseyeKoEtZf8PZYzGFXFCuuYGkb6oALUuRsGD69Y8mDYDRBRcuWAnkCUScL
transaction signature, 87:  ku85vTSmTy5hkHfoykQx3nw13wsRxU6Py9FSYbrgqCHti4fWPR9AnffPn2buXB16TJyva9wb8k28cjmHZ7vT6hf
zeroed 64-byte journal:     1111111111111111111111111111111111111111111111111111111111111111
ADDRESSES
  git -C "${repo}" add -A && git -C "${repo}" commit -q -m clean
  if ! scan "${repo}" >/dev/null; then
    echo "self-test FAILED: clean repository was rejected" >&2
    return 1
  fi

  # 2. Each planted secret is caught, by path or by content.
  local fake_key b58_keypair
  fake_key="[$(seq -s, 1 64)]"
  mkdir -p "${repo}/solana/deploy" "${repo}/runtime/protocol" "${repo}/docker/ipfs" "${repo}/notes"
  printf '%s\n' "${fake_key}" > "${repo}/solana/deploy/kswarm_protocol-keypair.json"
  printf '%s\n' "${fake_key}" > "${repo}/notes/looks-harmless.json"
  printf 'const k = %s;\n' "${fake_key}" > "${repo}/notes/embedded.mjs"
  printf '{"wallet":{"secretKey":%s}}\n' "${fake_key}" > "${repo}/notes/nested.json"
  printf '/key/swarm/psk/1.0.0/\n/base16/\n%s\n' "$(printf 'ab%.0s' $(seq 1 32))" > "${repo}/docker/ipfs/swarm.key"
  printf -- '-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----\n' "$(printf 'MIIB%.0s' $(seq 1 16))" > "${repo}/notes/server.txt"
  # THE PLANTED BYPASS: the same kind of 64-byte key the JSON-array rule catches,
  # in the form a wallet exports it and a person pastes into a chat window. The
  # bytes are RFC 8032 test vector 1 -- the standard's own published value, not
  # anybody's key -- so the plant is a real, verifiable Solana keypair rather than
  # a lookalike, and the check that catches it is the ed25519 relation.
  #
  # The seed and the public key are written here as the RFC writes them, in hex,
  # and encoded at run time. Holding the base58 form as a literal would put a real
  # keypair in this file, and this script would then, correctly, refuse its own
  # repository. Encoding is not deriving: the public key below is the standard's
  # constant, not something ed25519_public_key() produced, so the plant does not
  # inherit a fault in the code it exists to test.
  b58_keypair="$(python3 <<'BASE58'
raw = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
number = int.from_bytes(raw, "big")
encoded = ""
while number:
    number, remainder = divmod(number, 58)
    encoded = alphabet[remainder] + encoded
print("1" * (len(raw) - len(raw.lstrip(b"\0"))) + encoded)
BASE58
)"
  [ "${#b58_keypair}" -eq 88 ] || {
    echo "self-test FAILED: the planted keypair encoded to ${#b58_keypair} characters, not 88" >&2
    return 1
  }
  printf 'exported from the wallet UI:\n%s\n' "${b58_keypair}" > "${repo}/notes/wallet-export.txt"
  printf '{"privateKey":"%s"}\n' "${b58_keypair}" > "${repo}/notes/wallet-export.json"
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
    "content notes/wallet-export.txt: base58 64-byte Solana keypair" \
    "content notes/wallet-export.json: base58 64-byte Solana keypair" \
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
  echo "self-test OK: clean repository accepted with its public keys and signatures untouched, $(grep -c . <<<"${output}") findings reported for planted files"
}

scan() {
  local repo="$1"
  git -C "${repo}" rev-parse --show-toplevel >/dev/null
  python3 - "${repo}" <<'PY'
import hashlib
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

# A 64-byte Solana key encodes to 87 or 88 base58 characters; the window is wider
# than that because the decoded length, not the character count, is what decides.
# The lookarounds take maximal runs, so the string inside a pair of JSON quotes is
# examined whole and a longer base58 blob is not sliced into a false match.
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_INDEX = {char: index for index, char in enumerate(B58_ALPHABET)}
B58_RUN_RE = re.compile(
    rb"(?<![1-9A-HJ-NP-Za-km-z])[1-9A-HJ-NP-Za-km-z]{85,90}(?![1-9A-HJ-NP-Za-km-z])"
)

# Ed25519 public keys, RFC 8032 section 5.1.5, in the standard library only. This
# is the whole reason the base58 rule can be precise: a Solana secret key file is
# seed || public-key, so deriving the public key from the first 32 bytes and
# comparing it with the last 32 separates a wallet export from a 64-byte string
# that merely looks like one. The self-test checks this derivation against the
# published RFC 8032 vector before it trusts it.
ED_P = 2**255 - 19
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_I = pow(2, (ED_P - 1) // 4, ED_P)


def _ed_add(first, second):
    x1, y1, z1, t1 = first
    x2, y2, z2, t2 = second
    a = (y1 - x1) * (y2 - x2) % ED_P
    b = (y1 + x1) * (y2 + x2) % ED_P
    c = t1 * 2 * ED_D * t2 % ED_P
    d = z1 * 2 * z2 % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P)


def _ed_mul(point, scalar):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_base():
    y = 4 * pow(5, ED_P - 2, ED_P) % ED_P
    u = (y * y - 1) * pow(ED_D * y * y + 1, ED_P - 2, ED_P) % ED_P
    x = pow(u, (ED_P + 3) // 8, ED_P)
    if (x * x - u) % ED_P != 0:
        x = x * ED_I % ED_P
    if x % 2 != 0:
        x = ED_P - x
    return (x, y, 1, x * y % ED_P)


ED_B = _ed_base()


def ed25519_public_key(seed: bytes) -> bytes:
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    x, y, z, _ = _ed_mul(ED_B, scalar)
    inverse = pow(z, ED_P - 2, ED_P)
    x, y = x * inverse % ED_P, y * inverse % ED_P
    return ((y & ~(1 << 255)) | ((x & 1) << 255)).to_bytes(32, "little")


def b58_decode(text: str) -> bytes | None:
    number = 0
    for char in text:
        index = B58_INDEX.get(char)
        if index is None:
            return None
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    return b"\0" * (len(text) - len(text.lstrip("1"))) + body


def holds_base58_keypair(blob: bytes) -> bool:
    for match in B58_RUN_RE.finditer(blob):
        raw = b58_decode(match.group(0).decode("ascii"))
        if raw is None or len(raw) != 64:
            continue
        if ed25519_public_key(raw[:32]) == raw[32:]:
            return True
    return False


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
    if holds_base58_keypair(blob):
        return "base58 64-byte Solana keypair"
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
print(
    f"check-no-secrets: OK, {len(entries)} tracked files in the index; none has a forbidden "
    "path or holds one of the key shapes this script detects. History is not scanned."
)
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
