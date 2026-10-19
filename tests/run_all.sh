#!/usr/bin/env bash
# Runs every test offline: network, SMTP and Teams are mocked, nothing is sent.
# Each test gets its own temporary VULNSG_DIR, so no real state file is touched.
set -euo pipefail
cd "$(dirname "$0")"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run() {
    local title=$1; shift
    mkdir -p "$TMP/$1"
    echo "== $title"
    python3 "$@" "$TMP/$1" 2>&1 | grep -vE '^(Sending email|Email Sent|Teams alert sent|New KEV entries)' || true
    echo
}

run "Vraies fiches CVE.org (7 CVE du KEV, 13-15/10/2026)" test_real_kev_records.py
run "Cas limites du tri SG"                               test_score_cases.py
run "Rejeu de l'incident CVE-2026-96951"                  test_incident_replay.py
FAIL_MAIL=CVE-2026-96951 run "Rejeu, mail en echec sur 96951" test_incident_replay.py
run "Mode filtre SG de bout en bout"                      test_filtered_pipeline.py

# teams_only tests take the env dir first, then their own arguments.
for t in "test_teams_only.py --since 2026-10-17" "test_teams_only_assess.py"; do
    set -- $t
    mkdir -p "$TMP/$1"
    echo "== $1"
    python3 "$1" "$TMP/$1" "${@:2}"
    echo
done
