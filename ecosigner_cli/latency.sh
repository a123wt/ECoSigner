#!/usr/bin/env bash
set -u
# 不用 -e，避免单次失败导致整个脚本退出
set -o pipefail

PROXY="${PROXY:-http://127.0.0.1:8080}"
MODE="${MODE:-sign}"
N="${N:-30}"
OUT="${OUT:-latency.csv}"
SLEEP_MS="${SLEEP_MS:-0}"
IDENTITY="${IDENTITY:-test-key-1}"
TBS="${TBS:-NmpiMEX18m2nQ7lKg52kPu/KxbKA6Hb2A0uZEnka4BQ=}"


while [[ $# -gt 0 ]]; do
  case "$1" in
    --proxy) PROXY="$2"; shift 2;;
    --mode) MODE="$2"; shift 2;;
    --n) N="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    --sleep-ms) SLEEP_MS="$2"; shift 2;;
    --identity) IDENTITY="$2"; shift 2;;
    --tbs) TBS="$2"; shift 2;;
    --dkg-t) DKG_T="$2"; shift 2;;
    --dkg-n) DKG_N="$2"; shift 2;;
    *) echo "unknown arg: $1"; exit 1;;
  esac
done

command -v curl >/dev/null 2>&1 || { echo "missing tool: curl"; exit 1; }
command -v awk  >/dev/null 2>&1 || { echo "missing tool: awk"; exit 1; }
command -v date >/dev/null 2>&1 || { echo "missing tool: date"; exit 1; }

SIGN_URL="$PROXY/sign"
DKG_URL="$PROXY/dkg"

echo "iter,ts_ms,endpoint,http_code,latency_ms,request_index" > "$OUT"

gen_req_id() {
  local ts pid r
  ts="$(date +%s%3N)"
  pid="$$"
  r="$RANDOM$RANDOM"
  echo "${ts}-${pid}-${1}-${r}"
}

sleep_ms() {
  local ms="$1"
  if [[ "$ms" -gt 0 ]]; then
    local sec
    sec="$(awk -v ms="$ms" 'BEGIN { printf "%.3f", ms/1000 }')"
    sleep "$sec"
  fi
}

sec_to_ms() {
  awk -v s="$1" 'BEGIN { printf "%d", (s*1000)+0.5 }'
}

for i in $(seq 1 "$N"); do
  req_id="$(gen_req_id "$i")"
  ts_ms="$(date +%s%3N)"

  if [[ "$MODE" == "sign" ]]; then
    url="$SIGN_URL"
    body=$(cat <<JSON
{
  "tobesigned": "$TBS",
  "input_data_type": "Base64",
  "request_index": "$req_id",
  "identity": "$IDENTITY"
}
JSON
)
  elif [[ "$MODE" == "dkg" ]]; then
    url="$DKG_URL"
    body=$(cat <<JSON
{
  "request_index": "$req_id",
  "identity": "$IDENTITY"
}
JSON
)
  else
    echo "MODE must be sign|dkg"
    exit 1
  fi

  # 关键：不要让 curl 失败导致脚本退出
  out_line=""
  curl_rc=0
  out_line="$(curl -sS -o /dev/null \
      --connect-timeout 3 \
      --max-time 120 \
      -w "%{http_code} %{time_total}\n" \
      -H "Content-Type: application/json" \
      -X POST \
      --data "$body" \
      "$url" 2>/dev/null)" || curl_rc=$?

  # 若 curl 失败，填默认值
  if [[ $curl_rc -ne 0 || -z "$out_line" ]]; then
    http_code="000"
    time_total="0"
  else
    http_code="$(echo "$out_line" | awk '{print $1}')"
    time_total="$(echo "$out_line" | awk '{print $2}')"
  fi

  latency_ms="$(sec_to_ms "$time_total")"

  echo "${i},${ts_ms},${MODE},${http_code},${latency_ms},${req_id}" >> "$OUT"

  if [[ $curl_rc -ne 0 ]]; then
    echo "[$i/$N] mode=$MODE http=$http_code latency_ms=$latency_ms req_id=$req_id (curl_rc=$curl_rc)"
  else
    echo "[$i/$N] mode=$MODE http=$http_code latency_ms=$latency_ms req_id=$req_id"
  fi

  sleep_ms "$SLEEP_MS"
done

echo
echo "Saved: $OUT"
