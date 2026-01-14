#!/usr/bin/env bash
set -euo pipefail

# -------------------------
# Defaults (override via args)
# -------------------------
PROXY="${PROXY:-http://127.0.0.1:8080}"
DUR="${DUR:-20s}"          # wrk/vegeta duration
CONN="${CONN:-50}"         # connections
THREADS="${THREADS:-4}"    # wrk threads
QPS="${QPS:-500}"          # vegeta rate
PARTIES="${PARTIES:-[1,3]}" # json array string, e.g. [1,2,3]
IDENTITY="${IDENTITY:-test-key-1}"

# 32 bytes digest base64 (representative)
TBS="${TBS:-NmpiMEX18m2nQ7lKg52kPu/KxbKA6Hb2A0uZEnka4BQ=}"

TOOL="${1:-wrk}" # wrk|hey|vegeta
MODE="${2:-sign}" # sign|dkg

SIGN_URL="$PROXY/sign"
DKG_URL="$PROXY/dkg"

# payloads
SIGN_BODY=$(cat <<JSON
{
  "tobesigned": "$TBS",
  "parties": $PARTIES,
  "input_data_type": "Base64",
  "identity": "$IDENTITY"
}
JSON
)

DKG_BODY=$(cat <<JSON
{
  "threshold": 1,
  "number_of_parties": 3,
  "identity": "$IDENTITY"
}
JSON
)

# -------------------------
# helper: check tool
# -------------------------
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing tool: $1"; exit 1; }; }

# -------------------------
# run
# -------------------------
case "$MODE" in
  sign) URL="$SIGN_URL"; BODY="$SIGN_BODY";;
  dkg)  URL="$DKG_URL";  BODY="$DKG_BODY";;
  *) echo "MODE must be sign|dkg"; exit 1;;
esac

echo "== bench proxy =="
echo "tool=$TOOL mode=$MODE"
echo "url=$URL"
echo "dur=$DUR threads=$THREADS conn=$CONN qps=$QPS"
echo

case "$TOOL" in
  wrk)
    need wrk
    # wrk + lua: 固定 body，避免每次 spawn 外部进程影响吞吐
    TMP_LUA="$(mktemp /tmp/wrk_proxy.XXXXXX.lua)"
    cat > "$TMP_LUA" <<'LUA'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
-- body and url will be injected by env
wrk.body = os.getenv("WRK_BODY")

request = function()
  return wrk.format(nil, os.getenv("WRK_URL"), nil, wrk.body)
end
LUA

    WRK_URL="$URL" WRK_BODY="$BODY" wrk -t"$THREADS" -c"$CONN" -d"$DUR" "$URL" -s "$TMP_LUA"
    rm -f "$TMP_LUA"
    ;;

  hey)
    need hey
    # hey 自带并发/持续时间，输出响应码分布、QPS、延迟
    # 注意：hey 的 -z 使用 20s 这种格式
    hey -m POST -T "application/json" -z "$DUR" -c "$CONN" -d "$BODY" "$URL" >/dev/null \
      || true
    # hey 默认输出到 stdout，我们不丢弃，改为直接输出：
    hey -m POST -T "application/json" -z "$DUR" -c "$CONN" -d "$BODY" "$URL"
    ;;

  vegeta)
    need vegeta

    OUT_BIN="$(mktemp /tmp/vegeta_proxy.XXXXXX.bin)"

    # 1) attack -> file
    printf "POST %s\n" "$URL" \
      | vegeta attack -duration="$DUR" -rate="$QPS" \
          -header="Content-Type: application/json" \
          -body <(printf '%s' "$BODY") \
      > "$OUT_BIN"

    # 2) report summary
    vegeta report < "$OUT_BIN"

    # 3) report hist
    vegeta report -type='hist[0,10ms,25ms,50ms,100ms,250ms,500ms,1s,2s]' < "$OUT_BIN"

    rm -f "$OUT_BIN"
    ;;
esac
