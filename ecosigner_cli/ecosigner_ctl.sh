#!/usr/bin/env bash
set -euo pipefail

# ecosigner_ctl.sh
# One-click start/stop/status for: proxy(merged relay) + n nodes
#
# Creates:
#   <root>/log/*.log   (stdout+stderr)
#   <root>/pid/*.pid   (process ids)
#   <root>/pid/config.json (generated config used by proxy)
#
# Usage:
#   ./ecosigner_ctl.sh start  --root /path/to/run --n 3 --t 1 --proxy-bin ... --node-bin ...
#   ./ecosigner_ctl.sh stop   --root /path/to/run
#   ./ecosigner_ctl.sh status --root /path/to/run

cmd="${1:-}"
shift || true

die() { echo "Error: $*" >&2; exit 1; }
info() { echo "$*"; }

ROOT=""
N=""
T=""
PROXY_PORT="8080"
RELAY_PORT="8000"
HOST="127.0.0.1"
PROXY_BIND_ADDR="0.0.0.0"
TIMEOUT_MS="15000"
DKG_BASE_PORT="7000"
SIGN_BASE_PORT="7100"
SHARES_BASE=""
IDENTITY="test-key-1"
PROXY_BIN=""
NODE_BIN=""
NO_BUILD="0"

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --root) ROOT="${2:-}"; shift 2;;
      --n) N="${2:-}"; shift 2;;
      --t) T="${2:-}"; shift 2;;
      --proxy-port) PROXY_PORT="${2:-}"; shift 2;;
      --relay-port) RELAY_PORT="${2:-}"; shift 2;;
      --host) HOST="${2:-}"; shift 2;;
      --proxy-bind) PROXY_BIND_ADDR="${2:-}"; shift 2;;
      --timeout-ms) TIMEOUT_MS="${2:-}"; shift 2;;
      --dkg-base-port) DKG_BASE_PORT="${2:-}"; shift 2;;
      --sign-base-port) SIGN_BASE_PORT="${2:-}"; shift 2;;
      --shares-base) SHARES_BASE="${2:-}"; shift 2;;
      --identity) IDENTITY="${2:-}"; shift 2;;
      --proxy-bin) PROXY_BIN="${2:-}"; shift 2;;
      --node-bin) NODE_BIN="${2:-}"; shift 2;;
      --no-build) NO_BUILD="1"; shift;;
      -h|--help)
        sed -n '1,120p' "$0"
        exit 0
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done
}

is_int() { [[ "${1:-}" =~ ^[0-9]+$ ]]; }

ensure_root() {
  [[ -n "$ROOT" ]] || die "--root is required"
  # root 不存在则创建（满足一键）
  mkdir -p "$ROOT"
  ROOT="$(cd "$ROOT" && pwd)"
  [[ -n "$SHARES_BASE" ]] || SHARES_BASE="$ROOT"
  mkdir -p "$ROOT/log" "$ROOT/pid"
}

pid_file() { echo "$ROOT/pid/$1.pid"; }
log_file() { echo "$ROOT/log/$1.log"; }

start_proc() {
  local name="$1"; shift
  local pidf logf oldpid
  pidf="$(pid_file "$name")"
  logf="$(log_file "$name")"

  if [[ -f "$pidf" ]]; then
    oldpid="$(cat "$pidf" 2>/dev/null || true)"
    if [[ -n "$oldpid" ]] && kill -0 "$oldpid" 2>/dev/null; then
      info "[skip] $name already running (pid=$oldpid)"
      return 0
    fi
  fi

  info "[start] $name: $*"
  nohup "$@" >>"$logf" 2>&1 &
  local pid=$!
  echo "$pid" >"$pidf"
  info "[ok] $name pid=$pid log=$logf"
}

stop_proc() {
  local name="$1"
  local pidf pid
  pidf="$(pid_file "$name")"
  [[ -f "$pidf" ]] || return 0
  pid="$(cat "$pidf" 2>/dev/null || true)"
  [[ -n "$pid" ]] || { rm -f "$pidf"; return 0; }

  if kill -0 "$pid" 2>/dev/null; then
    info "[stop] $name pid=$pid"
    kill "$pid" 2>/dev/null || true
    for _ in {1..50}; do
      if ! kill -0 "$pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
      info "[kill -9] $name pid=$pid"
      kill -9 "$pid" 2>/dev/null || true
    fi
  fi
  rm -f "$pidf"
}

status_proc() {
  local name="$1"
  local pidf pid
  pidf="$(pid_file "$name")"
  if [[ ! -f "$pidf" ]]; then
    info "[down] $name (no pid file)"
    return 0
  fi
  pid="$(cat "$pidf" 2>/dev/null || true)"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    info "[up]   $name pid=$pid log=$(log_file "$name")"
  else
    info "[down] $name (stale pid file pid=$pid)"
  fi
}

write_config() {
  local cfg="$ROOT/pid/config.json"
  local node_ip="http://${HOST}"

  local nodes_json=""
  for ((i=1; i<=N; i++)); do
    local dkg_port=$((DKG_BASE_PORT + i))
    local sign_port=$((SIGN_BASE_PORT + i))
    local entry
    entry=$(cat <<EOF
    { "index": $i, "ip": "$node_ip", "dkg_port": $dkg_port, "signing_port": $sign_port }
EOF
)
    if [[ $i -lt $N ]]; then
      nodes_json+="$entry,\n"
    else
      nodes_json+="$entry\n"
    fi
  done

  cat >"$cfg" <<EOF
{
  "proxy_bind": "${PROXY_BIND_ADDR}:${PROXY_PORT}",
  "relay_port": ${RELAY_PORT},
  "timeout_ms": ${TIMEOUT_MS},

  "identity": "${IDENTITY}",
  "threshold": ${T},
  "number_of_parties": ${N},
  "nodes": [
$(printf "%b" "$nodes_json")  ]
}
EOF

  echo "$cfg"
}

start_all() {
  [[ -n "$N" ]] || die "--n is required"
  [[ -n "$T" ]] || die "--t is required"
  is_int "$N" || die "--n must be integer"
  is_int "$T" || die "--t must be integer"
  [[ "$N" -ge 1 ]] || die "--n must be >=1"
  [[ "$T" -ge 0 ]] || die "--t must be >=0"
  [[ "$((T+1))" -le "$N" ]] || die "Need t+1 <= n (got t=$T n=$N)"

  ensure_root

  [[ -n "$PROXY_BIN" ]] || die "--proxy-bin is required (binary unknown as you said)"
  [[ -x "$PROXY_BIN" ]] || die "proxy binary not executable: $PROXY_BIN"

  [[ -n "$NODE_BIN" ]] || die "--node-bin is required (binary unknown as you said)"
  [[ -x "$NODE_BIN" ]] || die "node binary not executable: $NODE_BIN"

  local cfg
  cfg="$(write_config)"
  info "[config] wrote $cfg"

  # start proxy (merged relay inside proxy)
  start_proc "proxy" \
    "$PROXY_BIN" \
    --config "$cfg" \
    --bind "${PROXY_BIND_ADDR}:${PROXY_PORT}" \
    --relay-port "$RELAY_PORT" \
    --timeout-ms "$TIMEOUT_MS"

  # start nodes
  for ((i=1; i<=N; i++)); do
    local dkg_port=$((DKG_BASE_PORT + i))
    local sign_port=$((SIGN_BASE_PORT + i))
    start_proc "node${i}" \
      "$NODE_BIN" \
      --index "$i" \
      --dkg-listen-port "$dkg_port" \
      --signing-listen-port "$sign_port" \
      -c "http://${HOST}:${RELAY_PORT}/" \
      --shares-base "$SHARES_BASE"
  done

  info "[done] started proxy + $N nodes"
  info "       logs: $ROOT/log"
  info "       pids: $ROOT/pid"
}

stop_all() {
  ensure_root
  # nodes first
  shopt -s nullglob
  local pids=( "$ROOT/pid"/node*.pid )
  shopt -u nullglob
  if [[ ${#pids[@]} -gt 0 ]]; then
    for f in "${pids[@]}"; do
      local name
      name="$(basename "$f" .pid)"
      stop_proc "$name"
    done
  fi
  stop_proc "proxy"
  info "[done] stopped all"
}

status_all() {
  ensure_root
  status_proc "proxy"

  shopt -s nullglob
  local pids=( "$ROOT/pid"/node*.pid )
  shopt -u nullglob
  if [[ ${#pids[@]} -gt 0 ]]; then
    for f in "${pids[@]}"; do
      local name
      name="$(basename "$f" .pid)"
      status_proc "$name"
    done
  fi

  [[ -f "$ROOT/pid/config.json" ]] && info "[config] $ROOT/pid/config.json"
}

parse_args "$@"

case "$cmd" in
  start) start_all;;
  stop|kill) stop_all;;
  status) status_all;;
  *)
    die "Usage: $0 {start|stop|status} --root <dir> [--n N --t T ...]"
    ;;
esac
