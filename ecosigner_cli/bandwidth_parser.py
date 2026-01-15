#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


# 你的摘要日志格式：[broadcast] room=... sender=Some(x) receiver=None bytes=...
BROADCAST_RE = re.compile(
    r"""
    \[broadcast\]\s+
    room=(?P<room>\S+)\s+
    sender=Some\((?P<sender>\d+)\)\s+
    receiver=(?P<receiver>None|Some\(\d+\))\s+
    bytes=(?P<bytes>\d+)
    """,
    re.VERBOSE,
)
RECEIVER_SOME_RE = re.compile(r"Some\((\d+)\)")

# 固定轮数要求
ROUND_COUNTS = {"dkg": 4, "sign": 7}


@dataclass(frozen=True)
class Event:
    room: str
    sender: int
    receiver: Optional[int]  # None => broadcast
    bytes: int
    seq: int                 # order within room


def room_base(room: str) -> str:
    # signing_room_xxx-offline / -online 合并
    if room.startswith("signing_room_") and (room.endswith("-offline") or room.endswith("-online")):
        return room.rsplit("-", 1)[0]
    return room


def op_type(room_or_base: str) -> str:
    if room_or_base.startswith("dkg_room_"):
        return "dkg"
    if room_or_base.startswith("signing_room_"):
        return "sign"
    return "unknown"


def stage_of_room(room: str) -> str:
    if room.endswith("-offline"):
        return "offline"
    if room.endswith("-online"):
        return "online"
    return ""


def size_bucket(n: int, large: int, medium: int) -> str:
    if n >= large:
        return "L"
    if n >= medium:
        return "M"
    return "S"


def infer_raw_rounds(events: List[Event], large: int, medium: int) -> Dict[int, int]:
    """
    先做一个“原始轮次”启发式，用来分段（不保证轮数正确）
    raw_round increments when (is_broadcast, size_bucket) changes compared to previous event.
    """
    rounds: Dict[int, int] = {}
    cur = 1
    prev_sig = None
    for e in events:
        sig = (e.receiver is None, size_bucket(e.bytes, large, medium))
        if prev_sig is None:
            prev_sig = sig
        elif sig != prev_sig:
            cur += 1
            prev_sig = sig
        rounds[e.seq] = cur
    return rounds


def map_to_fixed_rounds(
    events: List[Event], op: str, raw_round_of_seq: Dict[int, int]
) -> Dict[int, int]:
    """
    将 raw_round 映射到固定轮数：
      - dkg: 1..4
      - sign: 1..7
    规则：
      1) 若 raw_max >= N：按比例压缩到 1..N（单调不回退）
      2) 若 raw_max < N：按 seq 均匀铺到 1..N（避免只出现 1..raw_max）
    """
    n = ROUND_COUNTS.get(op)
    if not n or op == "unknown":
        return {e.seq: raw_round_of_seq.get(e.seq, 1) for e in events}

    total = len(events)
    if total == 0:
        return {}

    raw_max = max(raw_round_of_seq.values()) if raw_round_of_seq else 1
    fixed: Dict[int, int] = {}

    if raw_max >= n:
        # 比例压缩：raw in [1..raw_max] -> [1..n]
        for e in events:
            raw = raw_round_of_seq.get(e.seq, 1)
            mapped = 1 + (raw - 1) * n // raw_max
            if mapped < 1:
                mapped = 1
            if mapped > n:
                mapped = n
            fixed[e.seq] = mapped
    else:
        # raw 不够：用 seq 均匀铺到 1..n
        for e in events:
            mapped = 1 + (e.seq - 1) * n // total
            if mapped < 1:
                mapped = 1
            if mapped > n:
                mapped = n
            fixed[e.seq] = mapped

    return fixed


def parse_log(path: Path) -> Dict[str, List[Event]]:
    by_room: Dict[str, List[Event]] = defaultdict(list)
    seq_counter: Dict[str, int] = defaultdict(int)

    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = BROADCAST_RE.search(line)
            if not m:
                continue

            room = m.group("room")
            sender = int(m.group("sender"))
            receiver_raw = m.group("receiver")
            b = int(m.group("bytes"))

            receiver: Optional[int] = None
            if receiver_raw != "None":
                mm = RECEIVER_SOME_RE.search(receiver_raw)
                receiver = int(mm.group(1)) if mm else None

            seq_counter[room] += 1
            by_room[room].append(
                Event(room=room, sender=sender, receiver=receiver, bytes=b, seq=seq_counter[room])
            )

    return by_room


def compute_participants(events: List[Event]) -> Set[int]:
    s: Set[int] = set()
    for e in events:
        s.add(e.sender)
        if e.receiver is not None:
            s.add(e.receiver)
    return s


def main():
    ap = argparse.ArgumentParser(description="Parse MPC proxy logs -> messages.csv + bandwidth.csv")
    ap.add_argument("logfile", type=Path, help="path to log file (e.g. proxy.log)")
    ap.add_argument("--outdir", type=Path, default=Path("."), help="output directory")
    ap.add_argument("--messages", type=str, default="messages.csv", help="messages csv filename")
    ap.add_argument("--bandwidth", type=str, default="bandwidth.csv", help="bandwidth csv filename")
    ap.add_argument("--large", type=int, default=8000, help="bytes threshold for 'L' bucket (raw round heuristic)")
    ap.add_argument("--medium", type=int, default=2000, help="bytes threshold for 'M' bucket (raw round heuristic)")
    args = ap.parse_args()

    by_room = parse_log(args.logfile)

    outdir = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)

    messages_path = outdir / args.messages
    bandwidth_path = outdir / args.bandwidth

    # message rows（广播展开后）
    msg_rows: List[Dict] = []

    # 带宽统计：key 改成 (room_base, node) —— 不区分 offline/online
    bw: Dict[Tuple[str, int], List[int]] = defaultdict(lambda: [0, 0])  # [uplink, downlink]

    # 为了广播展开，需要知道每个 room_base 的参与者集合（合并 offline/online）
    participants_by_base: Dict[str, Set[int]] = defaultdict(set)

    # 先收集 base 参与者集合
    for room, events in by_room.items():
        base = room_base(room)
        participants_by_base[base].update(compute_participants(events))

    # 处理每个原始 room（messages 里保留 stage，round 用固定轮数映射）
    for room, events in by_room.items():
        base = room_base(room)
        op = op_type(base)
        stg = stage_of_room(room)

        participants = participants_by_base.get(base, set())
        k = len(participants)
        if k <= 1:
            continue
        participants_sorted = sorted(participants)

        raw_round_of_seq = infer_raw_rounds(events, large=args.large, medium=args.medium)
        fixed_round_of_seq = map_to_fixed_rounds(events, op, raw_round_of_seq)

        for e in events:
            rnd = fixed_round_of_seq.get(e.seq, 1)

            if e.receiver is None:
                # broadcast: expand to each other participant
                for r in participants_sorted:
                    if r == e.sender:
                        continue

                    # sender uplink: counts once per receiver
                    bw[(base, e.sender)][0] += e.bytes
                    # receiver downlink
                    bw[(base, r)][1] += e.bytes

                    msg_rows.append(
                        {
                            "op": op,
                            "room_base": base,
                            "room_raw": room,
                            "stage": stg,
                            "round": rnd,
                            "seq_in_room": e.seq,
                            "sender": e.sender,
                            "receiver": r,
                            "is_broadcast": 1,
                            "bytes": e.bytes,
                            "participants_k": k,
                        }
                    )
            else:
                bw[(base, e.sender)][0] += e.bytes
                bw[(base, e.receiver)][1] += e.bytes

                msg_rows.append(
                    {
                        "op": op,
                        "room_base": base,
                        "room_raw": room,
                        "stage": stg,
                        "round": rnd,
                        "seq_in_room": e.seq,
                        "sender": e.sender,
                        "receiver": e.receiver,
                        "is_broadcast": 0,
                        "bytes": e.bytes,
                        "participants_k": k,
                    }
                )

    # write messages.csv
    msg_fields = [
        "op",
        "room_base",
        "room_raw",
        "stage",
        "round",
        "seq_in_room",
        "sender",
        "receiver",
        "is_broadcast",
        "bytes",
        "participants_k",
    ]
    with messages_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=msg_fields)
        w.writeheader()
        for row in msg_rows:
            w.writerow(row)

    # write bandwidth.csv（不区分 offline/online，只按 room_base 聚合）
    bw_fields = ["op", "room_base", "node", "uplink_bytes", "downlink_bytes", "total_bytes"]
    with bandwidth_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=bw_fields)
        w.writeheader()
        for (base, node), (up, down) in sorted(bw.items(), key=lambda x: (x[0][0], x[0][1])):
            op = op_type(base)
            w.writerow(
                {
                    "op": op,
                    "room_base": base,
                    "node": node,
                    "uplink_bytes": up,
                    "downlink_bytes": down,
                    "total_bytes": up + down,
                }
            )

    print(f"OK: wrote {messages_path} ({len(msg_rows)} rows)")
    print(f"OK: wrote {bandwidth_path} ({len(bw)} rows)")


if __name__ == "__main__":
    main()
