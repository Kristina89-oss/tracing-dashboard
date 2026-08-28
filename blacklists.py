"""
Address screening against lists of "known bad" counterparties:

1. OFAC SDN -- sanctioned ETH addresses from the US Treasury. Source: an
   open, regularly updated CSV (the ultrasoundmoney/ofac-ethereum-addresses
   project, which auto-parses the Treasury's official sdn_advanced.xml).
2. Tether (USDT) blacklist -- addresses ever frozen by the USDT issuer
   directly in the contract (0xdac17f...831ec). Two check modes:
   - "currently frozen" -- a direct call to isBlackListed(address) on the
     contract;
   - "ever frozen" -- the history of AddedBlackList/RemovedBlackList events
     via the Etherscan Logs API (topic0 computed locally via keccak, see
     _topic()).
3. ScamSniffer scam-database -- an open, daily-updated blocklist of
   phishing ETH addresses (GitHub, no key required).
4. Manual Chainabuse sample (chainabuse_manual.json) -- the little that
   could be collected by browsing chainabuse.com's public feed while the
   monthly API quota is exhausted. Not a replacement for ScamSniffer, just
   a small addition.

Lists are cached to disk (the .cache/ folder) to avoid hitting the network
on every check -- refreshed once every CACHE_TTL seconds.
"""

from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path

import requests
from Crypto.Hash import keccak

CACHE_DIR = Path(__file__).parent / ".cache"
CACHE_TTL = 24 * 3600

OFAC_CSV_URL = "https://raw.githubusercontent.com/ultrasoundmoney/ofac-ethereum-addresses/main/data.csv"
SCAMSNIFFER_URL = "https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/address.json"
CHAINABUSE_MANUAL_PATH = Path(__file__).parent / "chainabuse_manual.json"
KRISTINA_INVESTIGATIONS_PATH = Path(__file__).parent / "kristina_investigations.json"
THIRD_PARTY_INVESTIGATIONS_PATH = Path(__file__).parent / "third_party_investigations.json"
USDT_CONTRACT = "0xdac17f958d2ee523a2206206994597c13d831ec"


def _topic(signature: str) -> str:
    h = keccak.new(digest_bits=256)
    h.update(signature.encode())
    return "0x" + h.hexdigest()


TOPIC_ADDED_BLACKLIST = _topic("AddedBlackList(address)")
TOPIC_REMOVED_BLACKLIST = _topic("RemovedBlackList(address)")
SELECTOR_IS_BLACKLISTED = "0xe47d6060"


def _cache_path(name: str) -> Path:
    CACHE_DIR.mkdir(exist_ok=True)
    return CACHE_DIR / name


def _is_fresh(path: Path) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < CACHE_TTL


def norm_address(addr: str) -> str:
    """Normalization for comparison. ETH addresses (0x...) are case-
    insensitive, so it's safe to lowercase them. TRON and Solana addresses
    are base58(check), where case is meaningful (it's not a checksum, it's
    part of the data); folding case turns them into a different, non-
    existent address. So for anything not starting with "0x", the case is
    preserved as-is."""
    addr = addr.strip()
    return addr.lower() if addr.startswith("0x") else addr


# --- OFAC ------------------------------------------------------------------

def load_ofac_addresses() -> dict[str, str]:
    """{lowercased address: name from the sanctions list}. Best-effort: if
    the network is unavailable, returns whatever is in the cache (even if
    stale), otherwise {}."""
    path = _cache_path("ofac_eth.csv")
    if not _is_fresh(path):
        try:
            resp = requests.get(OFAC_CSV_URL, timeout=15)
            resp.raise_for_status()
            path.write_text(resp.text, encoding="utf-8")
        except requests.RequestException:
            pass  # fall back to whatever is already cached (if anything)

    if not path.exists():
        return {}
    reader = csv.DictReader(io.StringIO(path.read_text(encoding="utf-8")))
    return {row["address"].lower(): row["name"] for row in reader if row.get("address")}


# --- ScamSniffer ---------------------------------------------------------------

def load_scamsniffer_addresses() -> set[str]:
    """Open phishing-address blocklist, updated by them daily (the public
    copy lags by 7 days). Best-effort: on a network failure, returns
    whatever is cached."""
    path = _cache_path("scamsniffer_address.json")
    if not _is_fresh(path):
        try:
            resp = requests.get(SCAMSNIFFER_URL, timeout=15)
            resp.raise_for_status()
            path.write_text(resp.text, encoding="utf-8")
        except requests.RequestException:
            pass

    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return set()
    return {a.lower() for a in data}


# --- Manual Chainabuse sample -------------------------------------------------

def load_chainabuse_manual() -> set[str]:
    """A small local address list, manually collected by browsing
    chainabuse.com's public report feed (no API)."""
    if not CHAINABUSE_MANUAL_PATH.exists():
        return set()
    try:
        data = json.loads(CHAINABUSE_MANUAL_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return set()
    addrs = data.get("addresses", {})
    return {norm_address(a) for chain_list in addrs.values() for a in chain_list}


# --- Your own investigations (github.com/Kristina89-oss) ---------------------

def load_kristina_investigations() -> dict[str, dict]:
    """{address: {"case": case name, "repo_url": repo link,
    **extra fields from the registry}} -- collected from your published
    investigations. Victim-side addresses and clearly legitimate
    infrastructure (e.g. a gas sponsor) have already been excluded when the
    file was built."""
    if not KRISTINA_INVESTIGATIONS_PATH.exists():
        return {}
    try:
        data = json.loads(KRISTINA_INVESTIGATIONS_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    out: dict[str, dict] = {}
    for case in data.get("cases", []):
        for addr, meta in case.get("addresses", {}).items():
            out[norm_address(addr)] = {"case": case["name"], "repo_url": case["repo_url"], **meta}
    return out


def load_third_party_investigations() -> dict[str, dict]:
    """Same shape as load_kristina_investigations(), but for third-party
    investigations (not authored by this dashboard's user) -- an address
    only ends up here after verification: real evidence (artifact hashes,
    archive.ph snapshots), a clear victim/operator split. See
    third_party_investigations.json for a note on what was rejected during
    review and why."""
    if not THIRD_PARTY_INVESTIGATIONS_PATH.exists():
        return {}
    try:
        data = json.loads(THIRD_PARTY_INVESTIGATIONS_PATH.read_text(encoding="utf-8"))
    except ValueError:
        return {}
    out: dict[str, dict] = {}
    for case in data.get("cases", []):
        for addr, meta in case.get("addresses", {}).items():
            out[norm_address(addr)] = {"case": case["name"], "repo_url": case["repo_url"], **meta}
    return out


# --- Tether ------------------------------------------------------------------

def is_tether_blacklisted_now(client, address: str) -> bool:
    """Live check of isBlackListed(address) directly on the USDT contract."""
    padded = address.lower().replace("0x", "").rjust(64, "0")
    data = SELECTOR_IS_BLACKLISTED + padded
    result = client.raw("proxy", "eth_call", to=USDT_CONTRACT, data=data, tag="latest")
    return bool(result) and int(result, 16) == 1


def load_tether_blacklist_history(client) -> dict[str, dict]:
    """{address: {"added_at": unix_ts, "tx": hash, "removed_at": unix_ts|None}}
    -- the full history of USDT freezes on Ethereum since the feature was
    introduced."""
    path = _cache_path("tether_blacklist.json")
    if _is_fresh(path):
        return json.loads(path.read_text(encoding="utf-8"))

    history: dict[str, dict] = {}
    try:
        for topic0, kind in ((TOPIC_ADDED_BLACKLIST, "added"), (TOPIC_REMOVED_BLACKLIST, "removed")):
            page, offset = 1, 1000
            while True:
                batch = client.raw(
                    "logs", "getLogs",
                    address=USDT_CONTRACT, topic0=topic0,
                    fromBlock=0, toBlock="latest", page=page, offset=offset,
                )
                if not batch:
                    break
                for log in batch:
                    if len(log.get("topics", [])) < 2:
                        continue
                    addr = "0x" + log["topics"][1][-40:]
                    addr = addr.lower()
                    ts = int(log["timeStamp"], 16)
                    entry = history.setdefault(addr, {})
                    if kind == "added":
                        entry["added_at"] = ts
                        entry["tx"] = log["transactionHash"]
                    else:
                        entry["removed_at"] = ts
                if len(batch) < offset:
                    break
                page += 1
    except Exception:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
        return {}

    path.write_text(json.dumps(history), encoding="utf-8")
    return history


# --- Counterparty cross-reference ---------------------------------------------

def screen_counterparties(
    addresses: set[str], ofac: dict[str, str], tether_history: dict[str, dict],
    scamsniffer: set[str] | None = None, chainabuse_manual: set[str] | None = None,
    kristina: dict[str, dict] | None = None, third_party: dict[str, dict] | None = None,
) -> dict:
    """Intersection of a set of counterparty addresses with the sanctions/
    freeze/scam lists."""
    addresses = {a.lower() for a in addresses}
    ofac_hits = [{"address": a, "name": ofac[a]} for a in addresses if a in ofac]
    tether_hits = [
        {"address": a, **tether_history[a]} for a in addresses if a in tether_history
    ]
    scamsniffer_hits = [a for a in addresses if a in (scamsniffer or set())]
    chainabuse_manual_hits = [a for a in addresses if a in (chainabuse_manual or set())]
    kristina_hits = [
        {"address": a, **(kristina or {})[a]} for a in addresses if a in (kristina or {})
    ]
    third_party_hits = [
        {"address": a, **(third_party or {})[a]} for a in addresses if a in (third_party or {})
    ]
    return {
        "ofac": ofac_hits, "tether": tether_hits,
        "scamsniffer": scamsniffer_hits, "chainabuse_manual": chainabuse_manual_hits,
        "kristina": kristina_hits, "third_party": third_party_hits,
    }


# --- EOA / contract ----------------------------------------------------------

def is_contract(client, address: str) -> bool:
    """True if the address has bytecode (it's a smart contract, not a
    regular wallet/EOA). This matters for the "fresh wallet with a large
    turnover" heuristic -- a freshly deployed contract (e.g. a new DeFi
    protocol) isn't the same thing as a burner wallet."""
    code = client.raw("proxy", "eth_getCode", address=address, tag="latest")
    return bool(code) and code not in ("0x", "0x0")
