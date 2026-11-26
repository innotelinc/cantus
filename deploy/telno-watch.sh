#!/usr/bin/env bash
# Watch the telephony path from the host that carries it.
#
# A dead relay and a dead trunk fail the way a working system does: quietly.
# Nothing rings, nothing logs an error a customer would see, and the first report
# is the customer's. So the probes a technician would run by hand run on a timer,
# and a *change of verdict* — not every run — goes to the estate's ntfy topic on
# .71. A long outage is one message; the recovery is another.
#
#  1. `cantus health --json` inside the node and the relay containers. With a
#     config the command refuses to pass unless the daemon already holds its
#     socket, then places a real call through a symmetric NAT with a rebind: the
#     relay has to carry it and the call has to survive.
#  2. 7443/tcp accepts a connection. The fallback binding is published; a
#     connection that is refused means a NAT that drops UDP has nowhere to go.
#  3. Telno's /api/healthz answers 200.
#  4. Asterisk reports at least one registered trunk. Without it every outbound
#     call fails at the carrier, which nothing local would notice: the switch
#     looks healthy and the trunk is simply gone.
#
# A probe that cannot be run is a failure, never a skip — a missing docker or a
# silent Asterisk is the outage. Credentials come from the estate's env file and
# reach curl on stdin, so they never appear in `ps`.
set -u -o pipefail

ENV_FILE=${NTFY_ENV_FILE:-/etc/innotel/ntfy.env}
STATE_DIR=${STATE_DIR:-/var/lib/telno-watch}
STATE_FILE="$STATE_DIR/last-verdict"
TELNO_HEALTH=${TELNO_HEALTH:-http://127.0.0.1:8080/api/healthz}

log() { printf '%s %s\n' "$(date -Is)" "$*"; }

fails=()
add() { fails+=("$1"); }

# cantus health inside the container that owns the socket: <container> <config> <label>
health_in() {
  local out code
  out=$(timeout 90 docker exec "$1" perl -Ilib bin/cantus health --config "$2" --json 2>&1)
  code=$?
  if [ "$code" -ne 0 ] || ! printf '%s' "$out" | grep -q '"ok":true'; then
    add "cantus-$3: ${out:-no output} (exit $code)"
  fi
}

tcp_probe() {
  if ! timeout 5 bash -c 'exec 3<>/dev/tcp/127.0.0.1/7443' 2>/dev/null; then
    add "cantus-tcp: 7443/tcp refused connection (the UDP fallback is not published)"
  fi
}

telno_probe() {
  local code
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$TELNO_HEALTH" 2>/dev/null)
  [ "$code" = "200" ] || add "telno-healthz: HTTP ${code:-no answer} from $TELNO_HEALTH"
}

trunk_probe() {
  local out count
  out=$(timeout 20 docker exec telno /usr/sbin/asterisk -rx 'pjsip show registrations' 2>&1)
  if [ $? -ne 0 ] || [ -z "$out" ]; then
    add "pjsip: Asterisk did not answer (the switch itself may be down)"
    return
  fi
  count=$(printf '%s\n' "$out" | grep -c 'Registered')
  [ "$count" -ge 1 ] || add "pjsip: 0 registered trunks — outbound calls will fail at the carrier"
}

notify() {  # title, priority, tags, body
  local code
  code=$(
    printf 'user = "%s:%s"\n' "$NTFY_USER" "$NTFY_PASSWORD" |
      curl -sS --max-time 20 -K - -o /dev/null -w '%{http_code}' \
        -H "Title: $1" -H "Priority: $2" -H "Tags: $3" \
        -H 'Content-Type: text/plain' \
        --data-binary "$4" "$URL/$TOPIC" 2>/dev/null
  )
  case "${code:-000}" in
    200) log "notified: $1" ;;
    *)   log "NOTIFY FAILED: $1 (HTTP ${code:-000})" ; return 1 ;;
  esac
}

[ -r "$ENV_FILE" ] || { log "CANNOT RUN: $ENV_FILE is not readable"; exit 2; }
# shellcheck disable=SC1090
. "$ENV_FILE"
URL=${NTFY_URL:-http://192.168.1.71:2586}
TOPIC=${NTFY_TOPIC:-}
[ -n "$TOPIC" ] || { log "CANNOT RUN: NTFY_TOPIC is not set"; exit 2; }
[ -n "${NTFY_USER:-}" ] && [ -n "${NTFY_PASSWORD:-}" ] || { log "CANNOT RUN: no ntfy credential"; exit 2; }

mkdir -p "$STATE_DIR"

health_in cantus-node  deploy/node.json  node
health_in cantus-relay deploy/relay.json relay
tcp_probe
telno_probe
trunk_probe

if [ ${#fails[@]} -gt 0 ]; then verdict=fail; else verdict=ok; fi

previous=$(cat "$STATE_FILE" 2>/dev/null || echo unknown)

if [ "$verdict" = ok ]; then
  body="All four probes pass: node and relay health, 7443/tcp, Telno healthz, at least one registered trunk. Checked from $(hostname) at $(date -Is)."
  title="telno: telephony recovered"
  priority=default
  tags=white_check_mark
else
  body=$(printf '%s\n' "${fails[@]}")
  body="Checked from $(hostname) at $(date -Is):"$'\n'"$body"
  if [ ${#fails[@]} -eq 1 ]; then
    title="telno: telephony down (1 probe failing)"
  else
    title="telno: telephony down (${#fails[@]} probes failing)"
  fi
  priority=high
  tags=rotating_light
fi

# The first run of a healthy install is not news; the first run of a broken one
# is exactly the alert this exists for.
if [ "$verdict" != "$previous" ] && { [ "$previous" != unknown ] || [ "$verdict" = fail ]; }; then
  notify "$title" "$priority" "$tags" "$body" || true
  log "verdict $previous -> $verdict"
else
  log "verdict $verdict (unchanged)"
fi

printf '%s\n' "$verdict" > "$STATE_FILE"
[ "$verdict" = ok ] || log "failing: ${fails[*]}"
exit 0
