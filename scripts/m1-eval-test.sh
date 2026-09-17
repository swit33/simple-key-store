#!/usr/bin/env bash
# m1-eval-test.sh -- M1 gate artifact for secrets-spec.md §5, §6, §11 and
# DECISIONS.md D9/D13/D21. It proves the one line the whole milestone exists
# for is safe to put in .zshenv:
#
#   eval "$(secrets export --format dotenv-export 2>/dev/null)"
#
# Concretely: the default export carries no ANSI, is clean under `sh -n`, and a
# clean `sh` sourcing it reproduces the stored bytes exactly -- a synthetic
# value with an embedded single quote and newline included -- while the emitted
# variable names equal the tracked scripts/expected-vars.txt. It also pins the
# two fail-closed contracts: a missing `get` is exit 2 with empty stdout, and
# `export` of a fresh empty environment is nonzero with empty stdout (a
# half-printed export is silently lost keys).
#
# Fixtures are synthetic (D13): the values are generated here; nothing is read
# from ~/.zshenv and nothing is printed. The run lives in one `mktemp -d` with
# HOME/XDG_* inside it, so no real user directory is touched. The binary is
# built into that sandbox because the gate runs task dependencies in parallel.

set -euo pipefail

fail() {
	printf 'm1-eval-test: FAIL: %s\n' "$1" >&2
	exit 1
}

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
expected_vars="$repo_root/scripts/expected-vars.txt"
[ -f "$expected_vars" ] || fail "missing tracked $expected_vars"

work=$(mktemp -d) || fail "mktemp -d"
cleanup() { rm -rf -- "$work"; }
trap cleanup EXIT

bin="$work/secrets"
(cd -- "$repo_root" && CGO_ENABLED=0 go build -o "$bin" ./cmd/secrets) ||
	fail "building cmd/secrets"

tag="$$_$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"

# Synthetic values. The quote and the newline are the point: they exercise the
# §6 POSIX quoting, and the shell metacharacters must survive verbatim.
v_deepseek="sks${tag}-deepseek-'quoted
second line \$HOME \`id\`"
v_searxng="sks${tag}-searxng-https://example.invalid/x?y=1&z=2"

sandbox="$work/sandbox"
export HOME="$sandbox/home"
export XDG_DATA_HOME="$sandbox/data"
export XDG_CONFIG_HOME="$sandbox/config"

printf '%s' "$v_deepseek" | "$bin" set deepseek/api_key --stdin || fail "set deepseek/api_key"
printf '%s' "$v_searxng" | "$bin" set searxng/api_url --stdin || fail "set searxng/api_url"

out="$work/export.out"
err="$work/export.err"
"$bin" export >"$out" 2>"$err" || fail "export exited nonzero"
[ -s "$out" ] || fail "export produced no output"
[ ! -s "$err" ] || fail "export wrote to stderr on success"

# No ANSI when stdout is a pipe (§6): a stray escape would poison `eval`.
if LC_ALL=C grep -q $'\033' "$out"; then
	fail "export output contains ANSI escape sequences"
fi

# The output is a valid POSIX shell fragment (§11: `export | sh -n` clean).
sh -n "$out" || fail "export output is not clean under sh -n"

# A clean shell sourcing the export must see exactly the stored bytes. The two
# variables are written to files so embedded newlines compare unambiguously.
env -i PATH=/usr/bin:/bin sh -c '
	. "$1" || exit 1
	printf "%s" "$DEEPSEEK_API_KEY" > "$2"
	printf "%s" "$SEARXNG_API_URL" > "$3"
' sh "$out" "$work/got_deepseek" "$work/got_searxng" || fail "sourcing the export in a clean sh failed"

printf '%s' "$v_deepseek" >"$work/exp_deepseek"
printf '%s' "$v_searxng" >"$work/exp_searxng"
cmp -s "$work/exp_deepseek" "$work/got_deepseek" ||
	fail "DEEPSEEK_API_KEY changed through quote/export/eval"
cmp -s "$work/exp_searxng" "$work/got_searxng" ||
	fail "SEARXNG_API_URL changed through quote/export/eval"

# The emitted names are exactly the tracked set, sorted (D13: path -> env name).
names="$work/names"
sed -n 's/^export \([A-Za-z_][A-Za-z0-9_]*\)=.*$/\1/p' "$out" | LC_ALL=C sort >"$names"
LC_ALL=C sort "$expected_vars" >"$work/expected-vars.sorted"
cmp -s "$work/expected-vars.sorted" "$names" ||
	fail "emitted variable names differ from scripts/expected-vars.txt"

# Missing key: exit 2, empty stdout (§6).
missing_rc=0
"$bin" get "sks/eval/absent" >"$work/missing.out" 2>"$work/missing.err" || missing_rc=$?
[ "$missing_rc" -eq 2 ] || fail "get on a missing path exited $missing_rc, want 2"
[ ! -s "$work/missing.out" ] || fail "get on a missing path wrote to stdout"

# Fresh, empty environment: export must fail closed with empty stdout (§5, D13).
empty="$work/empty"
export HOME="$empty/home"
export XDG_DATA_HOME="$empty/data"
export XDG_CONFIG_HOME="$empty/config"
empty_rc=0
"$bin" export >"$work/empty.out" 2>"$work/empty.err" || empty_rc=$?
[ "$empty_rc" -ne 0 ] || fail "export of a fresh empty environment succeeded, want nonzero"
[ ! -s "$work/empty.out" ] || fail "export of a fresh empty environment wrote to stdout"

printf 'm1-eval-test: OK (sh -n clean, clean eval exact, names match, fail-closed held)\n'
