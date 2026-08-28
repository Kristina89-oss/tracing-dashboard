"""
Heuristic scoring against money-laundering indicators drawn from the FATF
report ("Virtual Assets Red Flag Indicators", 2020) and standard AML
practice: mixer usage, sanctioned/frozen counterparties, structuring
(amounts just under reporting thresholds), rapid pass-through ("mule"
behavior), a fresh wallet with an immediately large turnover, abnormal
fan-out, round-numbered amounts.

These are HEURISTICS, not proof: each flag is a reason to look closer, not
an automatic conclusion of involvement in money laundering. Best-effort
rule: if there isn't enough data to check something (no ETH price, no
history, etc.), the flag simply isn't raised rather than erroring out.
"""

from __future__ import annotations

import time
from collections import defaultdict

STABLECOINS = {"USDT", "USDC", "DAI", "BUSD", "TUSD", "USDP", "FDUSD"}
STRUCTURING_THRESHOLDS = [10_000, 3_000]


def normalize_transfers(address: str, normal_txs: list[dict], erc20_txs: list[dict], eth_price_usd: float | None) -> list[dict]:
    address = address.lower()
    out = []
    for tx in normal_txs:
        value = int(tx["value"])
        if value == 0:
            continue
        amount = value / 10**18
        f, t = tx["from"].lower(), tx["to"].lower()
        out.append({
            "hash": tx["hash"], "from": f, "to": t, "timestamp": int(tx["timeStamp"]),
            "asset": "ETH", "amount": amount,
            "usd": amount * eth_price_usd if eth_price_usd else None,
            "direction": "out" if f == address else ("in" if t == address else "other"),
        })
    for tx in erc20_txs:
        decimals = int(tx.get("tokenDecimal", 18) or 18)
        amount = int(tx["value"]) / 10**decimals
        symbol = tx.get("tokenSymbol", "?")
        f, t = tx["from"].lower(), tx["to"].lower()
        out.append({
            "hash": tx["hash"], "from": f, "to": t, "timestamp": int(tx["timeStamp"]),
            "asset": symbol, "amount": amount,
            "usd": amount if symbol.upper() in STABLECOINS else None,
            "direction": "out" if f == address else ("in" if t == address else "other"),
        })
    out.sort(key=lambda x: x["timestamp"])
    return out


def _flag(id_, title, severity, hit, detail, evidence=None):
    return {"id": id_, "title": title, "severity": severity, "hit": hit, "detail": detail, "evidence": evidence or []}


def _detect_structuring(transfers: list[dict]) -> list[dict]:
    hits = []
    for threshold in STRUCTURING_THRESHOLDS:
        matches = [
            t for t in transfers
            if t["usd"] is not None and threshold * 0.8 <= t["usd"] < threshold
        ]
        if len(matches) >= 3:
            hits.append({"threshold": threshold, "count": len(matches), "examples": matches[:5]})
    return hits


def _detect_passthrough(transfers: list[dict], window_sec: int = 2 * 3600) -> list[dict]:
    hits = []
    incoming = [t for t in transfers if t["direction"] == "in" and t["usd"] and t["usd"] >= 1000]
    outgoing = sorted([t for t in transfers if t["direction"] == "out" and t["usd"]], key=lambda x: x["timestamp"])
    for inc in incoming:
        window = [o for o in outgoing if inc["timestamp"] < o["timestamp"] <= inc["timestamp"] + window_sec]
        moved = sum(o["usd"] for o in window)
        if window and moved >= 0.8 * inc["usd"]:
            hits.append({"in": inc, "out_count": len(window), "moved_usd": moved})
    return hits


def evaluate(
    address: str,
    normal_txs: list[dict],
    erc20_txs: list[dict],
    eth_price_usd: float | None,
    tornado_hits: list[dict],
    ofac_self_hit: dict | None,
    ofac_counterparty_hits: list[dict],
    tether_self_frozen: bool,
    tether_counterparty_hits: list[dict],
    goplus_hits: dict[str, str] | None = None,
    ransomlook_match: dict | None = None,
    scamsniffer_self_hit: bool = False,
    scamsniffer_counterparty_hits: list[str] | None = None,
    chainabuse_manual_self_hit: bool = False,
    chainabuse_manual_counterparty_hits: list[str] | None = None,
    kristina_self_hit: dict | None = None,
    kristina_counterparty_hits: list[dict] | None = None,
    third_party_self_hit: dict | None = None,
    third_party_counterparty_hits: list[dict] | None = None,
    is_contract: bool | None = None,
) -> dict:
    transfers = normalize_transfers(address, normal_txs, erc20_txs, eth_price_usd)
    now = time.time()
    flags = []

    flags.append(_flag(
        "sanctions_direct", "Address on the OFAC sanctions list", "critical",
        bool(ofac_self_hit),
        f"The address itself was found on the OFAC SDN list as \"{ofac_self_hit['name']}\"." if ofac_self_hit
        else "Address not found on the OFAC sanctions list (ETH).",
    ))

    flags.append(_flag(
        "sanctions_counterparty", "Direct transfers to/from sanctioned addresses", "high",
        bool(ofac_counterparty_hits),
        (f"Found {len(ofac_counterparty_hits)} counterpart(y/ies) from the OFAC list: "
         + "; ".join(f"{h['address']} ({h['name']})" for h in ofac_counterparty_hits))
        if ofac_counterparty_hits else "No OFAC-listed addresses among counterparties.",
    ))

    flags.append(_flag(
        "tether_frozen_self", "Address is currently frozen by Tether", "critical",
        tether_self_frozen,
        "The USDT contract returns isBlackListed=true for this address — USDT funds are frozen." if tether_self_frozen
        else "Address is not on the current USDT blacklist.",
    ))

    flags.append(_flag(
        "tether_frozen_counterparty", "Counterparties ever frozen by Tether", "high",
        bool(tether_counterparty_hits),
        f"Found {len(tether_counterparty_hits)} counterpart(y/ies) Tether has frozen in USDT (AddedBlackList history)."
        if tether_counterparty_hits else "No addresses from the USDT freeze history among counterparties.",
    ))

    flags.append(_flag(
        "mixer_tornado", "Tornado Cash interaction", "high",
        bool(tornado_hits),
        f"Direct interactions with Tornado Cash pools: {len(tornado_hits)}." if tornado_hits
        else "No direct interactions with Tornado Cash pools found.",
    ))

    goplus_hits = goplus_hits or {}
    flags.append(_flag(
        "goplus_reputation", "External sources flag this address as malicious (GoPlus/SlowMist/BlockSec)", "high",
        bool(goplus_hits),
        ("Labels found: " + ", ".join(goplus_hits.values())) if goplus_hits
        else "GoPlus/SlowMist/BlockSec found no malicious labels on this address.",
    ))

    flags.append(_flag(
        "ransomware", "Ransomware association", "critical",
        bool(ransomlook_match),
        (
            f"The address appears in RansomLook data, linked to the \"{ransomlook_match.get('family') or ransomlook_match.get('group')}\" group, "
            f"transactions: {ransomlook_match.get('tx_count', '?')}, balance ≈${ransomlook_match.get('balanceUSD') or 0:,.0f}."
        ) if ransomlook_match else "No match with known ransomware addresses (RansomLook).",
    ))

    scamsniffer_counterparty_hits = scamsniffer_counterparty_hits or []
    flags.append(_flag(
        "scamsniffer", "Phishing address per ScamSniffer", "high",
        scamsniffer_self_hit or bool(scamsniffer_counterparty_hits),
        (
            ("The address itself is on the ScamSniffer blocklist. " if scamsniffer_self_hit else "")
            + (f"Counterparties from the ScamSniffer blocklist: {len(scamsniffer_counterparty_hits)} — "
               + "; ".join(scamsniffer_counterparty_hits) if scamsniffer_counterparty_hits else "")
        ).strip() or "Neither the address nor its counterparties were found on the ScamSniffer blocklist.",
    ))

    chainabuse_manual_counterparty_hits = chainabuse_manual_counterparty_hits or []
    flags.append(_flag(
        "chainabuse_manual", "Found in the manual Chainabuse sample", "medium",
        chainabuse_manual_self_hit or bool(chainabuse_manual_counterparty_hits),
        (
            ("The address itself appears in the manually-collected Chainabuse sample. " if chainabuse_manual_self_hit else "")
            + (f"Counterparties from this sample: {len(chainabuse_manual_counterparty_hits)} — "
               + "; ".join(chainabuse_manual_counterparty_hits) if chainabuse_manual_counterparty_hits else "")
        ).strip() or "Not found in the small, manually-collected Chainabuse sample (see note — this sample isn't exhaustive).",
    ))

    # The user's own investigations (kristina_self_hit / kristina_counterparty_hits)
    # are deliberately not shown as a FATF flag and don't count toward the risk
    # score — that would be self-referential (your own findings shouldn't
    # "confirm" their own risk). They're shown in a separate block in the
    # template (see a.kristina_self / a.sanctions.kristina), not here.

    third_party_counterparty_hits = third_party_counterparty_hits or []
    third_party_detail_parts = []
    if third_party_self_hit:
        third_party_detail_parts.append(
            f"The address itself is named in the investigation \"{third_party_self_hit['case']}\" ({third_party_self_hit['repo_url']})."
        )
    for h in third_party_counterparty_hits:
        third_party_detail_parts.append(
            f"Counterparty {h['address']} is named in the investigation \"{h['case']}\" ({h['repo_url']})."
        )
    flags.append(_flag(
        "third_party_investigations", "Found in investigations", "high",
        bool(third_party_self_hit) or bool(third_party_counterparty_hits),
        " ".join(third_party_detail_parts) or "Not found in any tracked investigation.",
    ))

    structuring = _detect_structuring(transfers)
    flags.append(_flag(
        "structuring", "Possible structuring (amounts just under reporting thresholds)", "medium",
        bool(structuring),
        "; ".join(f"{h['count']} transfer(s) in the ${h['threshold']*0.8:,.0f}–${h['threshold']:,.0f} range" for h in structuring)
        if structuring else "No repeated amounts just under typical reporting thresholds ($3,000 / $10,000) found.",
    ))

    passthrough = _detect_passthrough(transfers)
    flags.append(_flag(
        "passthrough", "Rapid pass-through (received and almost immediately moved out)", "medium",
        bool(passthrough),
        f"{len(passthrough)} case(s) where ≥80% of a large incoming amount moved out again within 2 hours — "
        f"a typical pattern for a pass-through wallet in a laundering chain." if passthrough
        else "No signs of instant pass-through (received then immediately sent out) found.",
    ))

    first_seen = min((t["timestamp"] for t in transfers), default=None)
    age_days = (now - first_seen) / 86400 if first_seen else None
    cumulative_usd = sum(t["usd"] for t in transfers if t["usd"])
    # A smart contract (e.g. a new DeFi protocol) with an immediately large
    # turnover is normal and not the same thing as a burner wallet (EOA), so
    # this flag is only raised for regular addresses (EOAs), not contracts.
    new_wallet_hit = (
        age_days is not None and age_days <= 30 and cumulative_usd >= 10_000 and not is_contract
    )
    contract_note = " (this is a smart-contract address — the 'burner wallet' criterion doesn't apply to it)" if is_contract else ""
    flags.append(_flag(
        "new_wallet_high_volume", "Fresh wallet with an immediately large turnover", "medium",
        new_wallet_hit,
        (f"The wallet is {age_days:.0f} days old, but has already moved ≈${cumulative_usd:,.0f} in stablecoins — "
         f"typical of a one-off 'mule' wallet.") if new_wallet_hit
        else (f"The wallet is ≈{age_days:.0f} days old, stablecoin turnover ≈${cumulative_usd:,.0f}{contract_note} — doesn't look suspicious by this criterion."
              if age_days is not None else "Not enough transactions to estimate the wallet's age."),
    ))

    recent = [t for t in transfers if now - t["timestamp"] <= 30 * 86400]
    counterparties_30d = {t["to"] if t["direction"] == "out" else t["from"] for t in recent}
    counterparties_30d.discard(address.lower())
    high_fanout = len(counterparties_30d) >= 15
    flags.append(_flag(
        "high_fanout", "Many different counterparties in a short time", "low",
        high_fanout,
        f"{len(counterparties_30d)} unique counterparties in the last 30 days — "
        f"a possible sign of distribution/layering." if high_fanout
        else f"{len(counterparties_30d)} unique counterparties in the last 30 days — within normal range.",
    ))

    stable_transfers = [t for t in transfers if t["usd"] is not None]
    round_amounts = [t for t in stable_transfers if t["amount"] >= 100 and t["amount"] == round(t["amount"]) and t["amount"] % 100 == 0]
    round_hit = len(round_amounts) >= 5 and len(round_amounts) / max(len(stable_transfers), 1) >= 0.3
    flags.append(_flag(
        "round_amounts", "Many round-numbered transfers", "low",
        round_hit,
        f"{len(round_amounts)} out of {len(stable_transfers)} stablecoin transfers are round amounts (multiples of 100) — "
        f"typical of manual OTC settlements rather than organic use." if round_hit
        else "The share of round-numbered stablecoin transfers is within normal range.",
    ))

    weights = {"critical": 40, "high": 20, "medium": 10, "low": 5}
    score = sum(weights[f["severity"]] for f in flags if f["hit"])
    if score >= 60:
        level = "high"
    elif score >= 20:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "no clear indicators"

    # Hard rule: if the address turns up in your own investigations or in
    # ZachXBT's investigations, the level is immediately "high" regardless of
    # the sum of the other heuristics — this isn't a probabilistic estimate,
    # it's a direct match with an already-confirmed case.
    in_known_investigation = bool(
        kristina_self_hit or kristina_counterparty_hits
        or third_party_self_hit or third_party_counterparty_hits
    )
    if in_known_investigation:
        level = "high"
        score = max(score, 60)

    return {
        "flags": flags, "score": score, "level": level, "transfers": transfers,
        "is_contract": is_contract, "forced_high_risk": in_known_investigation,
    }
