#!/usr/bin/env bash
# Verify an OpenShell sandbox against the policy actually loaded in it.
#
#   ./scan.sh <sandbox>
#
# Pulls the sandbox's effective policy, converts it to JSON (neither the
# sandbox nor macOS python ships a YAML parser; ruby does), uploads both
# files and runs the assert mode. Exits non-zero on any mismatch, so it
# works as a policy regression gate in CI.
#
# For the no-policy report that runs anywhere, you do not need this:
#   python3 scan.py --report
set -euo pipefail

sb=${1:?usage: scan.sh <sandbox>}
shift || true

command -v openshell >/dev/null || { echo "openshell CLI not found" >&2; exit 1; }
command -v ruby      >/dev/null || { echo "ruby not found (needed for YAML)" >&2; exit 1; }

openshell sandbox get "$sb" --policy-only \
  | ruby -ryaml -rjson -e 'puts JSON.pretty_generate(YAML.load(STDIN.read))' \
  > policy.json

openshell sandbox upload "$sb" policy.json >/dev/null
openshell sandbox upload "$sb" scan.py     >/dev/null
openshell sandbox exec   "$sb" --no-tty -- python3 scan.py "$@"
