"""
Time-based analysis of wallet activity: a heatmap of transfers by time of
day/day of week, a check for a "too regular" schedule (a possible sign of
OTC settlements or automation), and the largest transactions.
"""

from __future__ import annotations

import statistics
import time

DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]


def build_heatmap(transfers: list[dict]) -> dict:
    """7x24 grid (UTC day of week x UTC hour) with transfer counts."""
    grid = [[0] * 24 for _ in range(7)]
    for t in transfers:
        st = time.gmtime(t["timestamp"])
        grid[st.tm_wday][st.tm_hour] += 1
    max_count = max((max(row) for row in grid), default=0)
    return {"grid": grid, "max": max_count, "days": DAYS}


def wallet_lifetime_note(transfers: list[dict]) -> str | None:
    """If the intervals between operations are suspiciously regular (low
    coefficient of variation), a pre-set schedule (OTC/bot) is likely. If
    there isn't enough data or the pattern is irregular, return None (don't
    claim anything)."""
    timestamps = sorted({t["timestamp"] for t in transfers})
    if len(timestamps) < 6:
        return None
    deltas = [b - a for a, b in zip(timestamps, timestamps[1:]) if b > a]
    if len(deltas) < 5:
        return None
    mean = statistics.mean(deltas)
    if mean <= 0:
        return None
    stdev = statistics.pstdev(deltas)
    cv = stdev / mean
    if cv >= 0.35:
        return None  # irregular pattern -- don't claim anything

    if mean < 3600:
        interval = f"{mean / 60:.0f} min"
    elif mean < 86400:
        interval = f"{mean / 3600:.1f} h"
    else:
        interval = f"{mean / 86400:.1f} d"

    return (
        f"Operations follow an unusually stable interval of ≈{interval} between them "
        f"(coefficient of variation {cv:.2f}) — this doesn't look like organic human use of "
        f"a wallet; a pre-set schedule is possible (OTC settlements, a bot, automation)."
    )


def top_transactions(transfers: list[dict], limit: int = 15) -> list[dict]:
    ranked = sorted(
        (t for t in transfers if t["usd"] is not None or t["asset"] == "ETH"),
        key=lambda t: (t["usd"] if t["usd"] is not None else 0),
        reverse=True,
    )
    return ranked[:limit]


def top_counterparties(transfers: list[dict], limit: int = 3) -> list[dict]:
    """Largest counterparties by total volume (incoming + outgoing transfers
    with them combined) -- not the single largest transaction, but who moved
    the most money through this address in total."""
    agg: dict[str, dict] = {}
    for t in transfers:
        if t["usd"] is None:
            continue
        counterparty = t["to"] if t["direction"] == "out" else t["from"]
        entry = agg.setdefault(counterparty, {"address": counterparty, "in_usd": 0.0, "out_usd": 0.0, "count": 0})
        entry["count"] += 1
        if t["direction"] == "out":
            entry["out_usd"] += t["usd"]
        else:
            entry["in_usd"] += t["usd"]

    for entry in agg.values():
        entry["total_usd"] = entry["in_usd"] + entry["out_usd"]

    ranked = sorted(agg.values(), key=lambda e: e["total_usd"], reverse=True)
    return ranked[:limit]
