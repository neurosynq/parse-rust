#!/usr/bin/env bash
# Gate K of 0.3.0: `docker compose up` from a fresh clone brings up a working server.
#
#   tools/demo/check.sh            clone HEAD into a temporary directory and check it
#   tools/demo/check.sh --staged   check the staged index instead, before it is committed
#
# **What a reader would do, not what the working tree happens to contain.** The check runs in a
# temporary directory with its own compose project name, so a stale image, a cached volume or a
# demo already running here cannot make it pass. It brings the demo up twice, tearing down with
# `down -v` in between, because a demo that only works once is a demo that works on one machine.
#
# Needs Docker and curl, and the demo's fixed port, 27800, free on 127.0.0.1.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
PROJECT="parse-rust-demo-check-$$"
BASE="http://127.0.0.1:27800/parse"
APP=(-H "X-Parse-Application-Id: demo")
MASTER=(-H "X-Parse-Master-Key: demo-master-key")
JSON=(-H "Content-Type: application/json")
FAILED=0
PASSED=0

# The exit status is kept: a trap's own last command would otherwise replace it, and a check that
# died half-way would report success.
cleanup() {
  local rc=$?
  ( cd "$WORK/repo" 2>/dev/null && docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1 ) || true
  rm -rf "$WORK"
  exit "$rc"
}
trap cleanup EXIT

fail() { echo "[FAIL] $*"; FAILED=1; }
ok()   { echo "[ ok ] $*"; PASSED=$((PASSED + 1)); }

if [[ "${1:-}" == "--staged" ]]; then
  mkdir -p "$WORK/repo"
  git -C "$REPO" checkout-index -a --prefix="$WORK/repo/"
  echo "checking the staged index in $WORK/repo"
else
  git clone --quiet "$REPO" "$WORK/repo"
  echo "checking a fresh clone of HEAD in $WORK/repo"
fi
cd "$WORK/repo"

# `body <field>` extracts one string field from the last response, without needing jq.
body() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p" <<<"$RESPONSE"; }

check_flow() {
  local round="$1"
  local user="demo_$$_$round" token id status
  # 1. Both containers healthy, polled by compose itself against each healthcheck, bounded.
  if docker compose -p "$PROJECT" up -d --build --wait --wait-timeout 600 >/dev/null 2>&1; then
    ok "round $round: parse-rust and MongoDB are healthy"
  else
    fail "round $round: a container did not become healthy"
    docker compose -p "$PROJECT" ps
    docker compose -p "$PROJECT" logs --tail 40
    return
  fi

  # 2. An SDK's first four calls: sign up, create, read back under the session, read the schema.
  RESPONSE=$(curl -fsS "${APP[@]}" "${JSON[@]}" -X POST "$BASE/users" \
    -d "{\"username\":\"$user\",\"password\":\"demo-password\"}") || { fail "round $round: signup"; return; }
  token=$(body sessionToken)
  [[ -n "$token" ]] && ok "round $round: signed up" || fail "round $round: signup returned no session"

  RESPONSE=$(curl -fsS "${APP[@]}" "${JSON[@]}" -H "X-Parse-Session-Token: $token" \
    -X POST "$BASE/classes/DemoItem" -d '{"title":"hello from the demo"}') || { fail "round $round: create"; return; }
  id=$(body objectId)
  [[ -n "$id" ]] && ok "round $round: created an object" || fail "round $round: create returned no objectId"

  RESPONSE=$(curl -fsS "${APP[@]}" -H "X-Parse-Session-Token: $token" "$BASE/classes/DemoItem/$id") \
    || { fail "round $round: read back"; return; }
  [[ "$(body title)" == "hello from the demo" ]] && ok "round $round: read it back under the session" \
    || fail "round $round: read back the wrong object: $RESPONSE"

  # 3. The master key from the host. The condition the compose file exists to get right: a request
  #    to a published port arrives from the bridge gateway, not from loopback.
  status=$(curl -s -o /dev/null -w '%{http_code}' "${APP[@]}" "${MASTER[@]}" "$BASE/schemas")
  [[ "$status" == "200" ]] && ok "round $round: the master key works from the host" \
    || fail "round $round: the master key was refused from the host ($status)"

  # 4. The control: no master key is still refused, so 3 cannot pass by disabling authorization.
  status=$(curl -s -o /dev/null -w '%{http_code}' "${APP[@]}" "$BASE/schemas")
  [[ "$status" == "403" ]] && ok "round $round: without the master key, /schemas is refused" \
    || fail "round $round: /schemas without the master key answered $status"
}

check_flow 1

# 5. `down -v` leaves nothing behind, and a second `up` from the same checkout works again.
docker compose -p "$PROJECT" down -v --remove-orphans >/dev/null 2>&1
if [[ -z "$(docker volume ls -q --filter "name=${PROJECT}_")" && -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  ok "down -v removed every container and volume"
else
  fail "down -v left something behind"
fi
check_flow 2

# The floor: six checks per round and the teardown check. A path that returned early without
# reaching an assertion must not read as clean.
EXPECTED=13
if [[ $PASSED -ne $EXPECTED ]]; then
  fail "$PASSED checks passed, expected exactly $EXPECTED"
fi

echo
if [[ $FAILED -eq 0 ]]; then echo "gate K: clean ($PASSED checks)"; else echo "gate K: FAILED"; fi
exit $FAILED
