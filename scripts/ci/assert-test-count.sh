#!/usr/bin/env bash
# Fail unless a test run reported exactly the number of passing tests we expect.
#
# A test command that collects nothing exits 0. So does one whose suite was
# silently narrowed by a bad marker, a missing dependency or a path that moved.
# Reading the count back out of the log is what separates "the suite passed"
# from "a suite passed".
#
# Usage:
#   scripts/ci/assert-test-count.sh <pytest|cargo|node> <expected> <log-file>
#
# <expected> is either a number, meaning exactly that many, or `>=N`, meaning at
# least N. Use the number where a suite's size is a fact worth pinning, and `>=`
# where the count is a floor that additions must be free to raise: the tier-1
# suite is the second kind, because a defect fix that arrives with new tests must
# not have to edit a pin in the same change to stay green. Both forms reject a
# shortfall, which is the failure this exists for; only the exact form also
# reports a suite that grew.
#
# The log is the combined stdout and stderr of the test command, kept as it was
# printed. Nothing here reruns the tests.
#
# Exit codes: 0 the log satisfies <expected> and reports no failures,
#             1 it does not, 2 the arguments or the log file are wrong.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <pytest|cargo|node> <expected> <log-file>" >&2
  exit 2
fi

kind="$1"
expected="$2"
log="$3"

floor_only=0
wanted="${expected}"
case "${expected}" in
  '>='*)
    floor_only=1
    wanted="${expected#>=}"
    ;;
esac
case "${wanted}" in
  ''|*[!0-9]*) echo "assert-test-count: expected count must be a number or >=number, got '${expected}'" >&2; exit 2 ;;
esac
if [ ! -f "${log}" ]; then
  echo "assert-test-count: no log at ${log}" >&2
  exit 2
fi

passed=0
failed=0

case "${kind}" in
  # `315 passed, 2 deselected in 4.44s`, or `1 failed, 150 passed, ... in 4.33s`.
  # A run that collected nothing prints `no tests ran`, which matches neither, so
  # the counts stay at zero and the comparison below rejects it.
  pytest)
    passed="$(grep -oE '[0-9]+ passed' "${log}" | tail -1 | cut -d' ' -f1 || true)"
    failed="$(grep -oE '[0-9]+ (failed|errors?)' "${log}" | tail -1 | cut -d' ' -f1 || true)"
    ;;
  # One `test result: ok. 65 passed; 0 failed; ...` line per test binary, so sum
  # them: a suite split across binaries is still one number.
  cargo)
    passed="$(grep -E '^test result:' "${log}" | grep -oE '[0-9]+ passed' | awk '{n+=$1} END {print n+0}' || true)"
    failed="$(grep -E '^test result:' "${log}" | grep -oE '[0-9]+ failed' | awk '{n+=$1} END {print n+0}' || true)"
    ;;
  # `node --test` prints a TAP summary: `# pass 44`, `# fail 0`.
  node)
    passed="$(grep -oE '^# pass [0-9]+' "${log}" | tail -1 | awk '{print $3}' || true)"
    failed="$(grep -oE '^# fail [0-9]+' "${log}" | tail -1 | awk '{print $3}' || true)"
    ;;
  *)
    echo "assert-test-count: unknown kind '${kind}' (pytest | cargo | node)" >&2
    exit 2
    ;;
esac

passed="${passed:-0}"
failed="${failed:-0}"

status=0
if [ "${failed}" -ne 0 ]; then
  echo "assert-test-count: ${log} reports ${failed} failing tests" >&2
  status=1
fi
if [ "${floor_only}" -eq 1 ]; then
  if [ "${passed}" -lt "${wanted}" ]; then
    echo "assert-test-count: ${log} reports ${passed} passing tests, fewer than the ${wanted} required" >&2
    echo "assert-test-count: a run that collects nothing still exits 0; that is what this rejects" >&2
    status=1
  fi
elif [ "${passed}" -ne "${wanted}" ]; then
  echo "assert-test-count: ${log} reports ${passed} passing tests, expected ${wanted}" >&2
  echo "assert-test-count: if the suite really changed size, change the expected count in the workflow" >&2
  status=1
fi
if [ "${status}" -eq 0 ]; then
  if [ "${floor_only}" -eq 1 ]; then
    echo "assert-test-count: ${passed} passing tests, at or above the required ${wanted}"
  else
    echo "assert-test-count: ${passed} passing tests, as expected"
  fi
fi
exit "${status}"
