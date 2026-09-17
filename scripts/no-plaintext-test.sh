#!/usr/bin/env bash
# no-plaintext-test.sh -- M1 gate artifact for secrets-spec.md §1, §5, §11 and
# DECISIONS.md D9/D15. It answers one question: does a value written through
# the client ever reach the disk as plaintext?
#
# The proof is behavioral: a unique synthetic marker goes in through
# `set --stdin`, comes back byte-for-byte through `get`, and is then searched
# for with `grep -a` in every file under the sandboxed client data directory --
# cache.db and its -wal/-shm siblings included, whichever happen to exist. Any
# hit, or any broken exit-code/stream contract, exits nonzero. The marker is
# never echoed: only the names of leaking files appear in diagnostics.
#
# Isolation: the whole run lives in one `mktemp -d` and HOME/XDG_DATA_HOME/
# XDG_CONFIG_HOME all point inside it, so no real user directory is read or
# written. The binary is built into that sandbox because the gate runs task
# dependencies in parallel and cannot rely on another task's build.

set -euo pipefail

fail() {
	printf 'no-plaintext-test: FAIL: %s\n' "$1" >&2
	exit 1
}

# contains_marker FILE -- true when FILE holds the marker verbatim.
contains_marker() {
	grep -a -q -F -e "$marker" -- "$1"
}

# no_marker_in LABEL FILE -- fail when FILE holds the marker.
no_marker_in() {
	if contains_marker "$2"; then
		fail "$1 leaks the plaintext marker"
	fi
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

work=$(mktemp -d) || fail "mktemp -d"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

bin="$work/secrets"
(cd -- "$repo_root" && CGO_ENABLED=0 go build -o "$bin" ./cmd/secrets) ||
	fail "building cmd/secrets"

# Unique, synthetic, shell-neutral marker (hex and underscores only).
marker="SKS_PLAINTEXT_MARKER_$$_$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
path="sks/plaintext/probe"

export HOME="$work/home"
export XDG_DATA_HOME="$work/data"
export XDG_CONFIG_HOME="$work/config"
data_dir="$XDG_DATA_HOME/secrets"

# Write: the value arrives on stdin only (§6), stdout stays empty, and the
# diagnostic stream must not name it.
printf '%s' "$marker" | "$bin" set "$path" --stdin >"$work/set.out" 2>"$work/set.err" ||
	fail "set exited nonzero"
[ ! -s "$work/set.out" ] || fail "set wrote to stdout"
no_marker_in "set stderr" "$work/set.err"

# Read: exact bytes, no added newline, no marker in the diagnostic stream.
"$bin" get "$path" >"$work/get.out" 2>"$work/get.err" || fail "get exited nonzero"
printf '%s' "$marker" >"$work/expected"
cmp -s "$work/expected" "$work/get.out" || fail "get did not round-trip the value byte for byte"
no_marker_in "get stderr" "$work/get.err"

# Listing prints paths, never values, on either stream.
"$bin" ls >"$work/ls.out" 2>"$work/ls.err" || fail "ls exited nonzero"
no_marker_in "ls stdout" "$work/ls.out"
no_marker_in "ls stderr" "$work/ls.err"

# A missing key is exit 2 with empty stdout (§6), and its diagnostic must not
# fall back to a cached value.
set +e
"$bin" get "sks/plaintext/absent" >"$work/missing.out" 2>"$work/missing.err"
missing_rc=$?
set -e
[ "$missing_rc" -eq 2 ] || fail "get on a missing path exited $missing_rc, want 2"
[ ! -s "$work/missing.out" ] || fail "get on a missing path wrote to stdout"
no_marker_in "missing-key stderr" "$work/missing.err"

# The cache must exist, otherwise the scan below proves nothing.
[ -d "$data_dir" ] || fail "client data dir $data_dir was not created"
[ -f "$data_dir/cache.db" ] || fail "cache.db was not created"

# Scan every file of the client data directory. `find` (not `grep -r`) so the
# -wal/-shm sidecars and any other artifact are covered explicitly.
scanned=0
hits=""
while IFS= read -r -d '' file; do
	scanned=$((scanned + 1))
	if contains_marker "$file"; then
		hits="$hits $file"
	fi
done < <(find "$data_dir" -type f -print0)
[ "$scanned" -gt 0 ] || fail "no file under $data_dir to scan"
[ -z "$hits" ] || fail "plaintext marker found in:$hits"

printf 'no-plaintext-test: OK (%d files scanned, marker absent)\n' "$scanned"
