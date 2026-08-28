"""
Local investigation dashboard: paste in an address or a transaction hash and
get everything that can be pulled from public sources on one page: FATF
scoring, sanctions/freezes, mixers/bridges, an activity heatmap, the largest
transactions, and OSINT from reports and web search.

Runs locally only (127.0.0.1), nothing is published anywhere.
"""

import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

import requests
from flask import Flask, render_template, request

BASE = Path(__file__).parent.parent
sys.path.insert(0, str(BASE / "etherscan-client"))
sys.path.insert(0, str(BASE / "chainabuse-client"))
sys.path.insert(0, str(BASE / "mixer-tracing-tools"))
sys.path.insert(0, str(Path(__file__).parent))

from etherscan_client import EtherscanClient, EtherscanError  # noqa: E402
from trace_mixer_exits import TORNADO_POOLS  # noqa: E402
from monero_price_correlation import check_event_for_anomaly  # noqa: E402

import blacklists  # noqa: E402
import external_intel  # noqa: E402
import fatf_flags  # noqa: E402
import timeline  # noqa: E402
import osint  # noqa: E402

app = Flask(__name__)
app.jinja_env.filters["strftime"] = lambda ts: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))

BRIDGETRAIL_API = "http://localhost:4001/api/trace"
BRIDGETRAIL_DIR = BASE / "bridgetrail"
BRIDGETRAIL_PORT = 4001
BRIDGETRAIL_CHAINS = ["ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche", "solana"]
EVM_CHAINS = {"ethereum", "arbitrum", "optimism", "base", "polygon", "bsc", "avalanche"}


def _port_open(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def ensure_bridgetrail_running() -> None:
    """Starts the bridgetrail web server (npm run web) in the background if
    it isn't running yet, so bridge tracing works right from the main page
    without a separate manual start. Best-effort: if node/npm aren't
    available or the directory isn't found, it just doesn't start it -- the
    regular "service unavailable" handling in run_bridgetrail() kicks in
    instead."""
    if _port_open(BRIDGETRAIL_PORT):
        print(f"bridgetrail is already responding on :{BRIDGETRAIL_PORT} -- not starting another one.")
        return
    if not (BRIDGETRAIL_DIR / "package.json").exists():
        print(f"bridgetrail not found in {BRIDGETRAIL_DIR} -- bridge tracing will be unavailable.")
        return
    try:
        log_path = Path(__file__).parent / ".cache" / "bridgetrail.log"
        log_path.parent.mkdir(exist_ok=True)
        log_file = open(log_path, "w", encoding="utf-8")
        # Important: explicitly set PORT=4001 in the child process's
        # environment. Otherwise bridgetrail inherits PORT from the parent
        # (its server also respects $PORT) -- if this dashboard itself is
        # running with PORT=5055 (e.g. from a preview panel), bridgetrail
        # would try to grab the same port 5055 and collide with Flask.
        child_env = dict(os.environ)
        child_env["PORT"] = str(BRIDGETRAIL_PORT)
        subprocess.Popen(
            "npm run web", shell=True, cwd=str(BRIDGETRAIL_DIR), env=child_env,
            stdout=log_file, stderr=subprocess.STDOUT,
        )
        for _ in range(20):  # up to ~10 seconds; usually comes up in 1-2s
            if _port_open(BRIDGETRAIL_PORT):
                print(f"bridgetrail started in the background on :{BRIDGETRAIL_PORT} (log: {log_path}).")
                return
            time.sleep(0.5)
        print(f"bridgetrail didn't respond within 10s -- check the log: {log_path}")
    except OSError as e:
        print(f"Couldn't start bridgetrail automatically ({e}) -- bridge tracing will be unavailable.")

TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
ETH_ADDRESS_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
BTC_ADDRESS_RE = re.compile(r"^(bc1[a-z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$")

STABLECOINS = {"USDT", "USDC", "DAI", "BUSD", "TUSD", "USDP", "FDUSD"}


# --- Local versions of the mixer checks, so we don't hit Etherscan again ----

def find_tornado_hits(normal_txs: list[dict], erc20_txs: list[dict]) -> list[dict]:
    hits = []
    for tx in normal_txs + erc20_txs:
        f, t = tx["from"].lower(), tx["to"].lower()
        if f in TORNADO_POOLS or t in TORNADO_POOLS:
            pool = TORNADO_POOLS.get(f) or TORNADO_POOLS.get(t)
            hits.append({"hash": tx["hash"], "pool": pool, "timestamp": int(tx["timeStamp"])})
    return hits


def find_mixer_candidates(address: str, erc20_txs: list[dict], known_graph: set[str], min_usd: float) -> list[dict]:
    address = address.lower()
    candidates = []
    for tx in erc20_txs:
        if tx["from"].lower() != address:
            continue
        to = tx["to"].lower()
        if to in known_graph or to in TORNADO_POOLS:
            continue
        symbol = tx.get("tokenSymbol", "")
        decimals = int(tx.get("tokenDecimal", 18) or 18)
        amount = int(tx["value"]) / 10**decimals
        usd = amount if symbol.upper() in STABLECOINS else None
        if usd is not None and usd >= min_usd:
            candidates.append({
                "hash": tx["hash"], "to": to, "amount": amount, "symbol": symbol,
                "usd_est": usd, "timestamp": int(tx["timeStamp"]),
                "date": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(int(tx["timeStamp"]))),
            })
    candidates.sort(key=lambda c: -c["usd_est"])
    return candidates


# --- Bridgetrail (reused by both the main page and /bridge) -----------------

def collect_leaves(node: dict, path: list[str] | None = None) -> list[dict]:
    path = (path or []) + [f"{node['chain']}:{node['tx']}"]
    children = node.get("children") or []
    if not children:
        return [{
            "chain": node["chain"], "tx": node["tx"], "address": node.get("address"),
            "stopReason": node.get("stopReason"), "path": " -> ".join(path),
        }]
    leaves = []
    for c in children:
        leaves.extend(collect_leaves(c, path))
    return leaves


def run_bridgetrail(chain: str, tx_hash: str, max_hops: int, fan_out: int) -> dict:
    try:
        resp = requests.post(
            BRIDGETRAIL_API,
            json={"chain": chain, "txHash": tx_hash, "maxHops": max_hops, "fanOut": fan_out},
            timeout=90,
        )
    except requests.RequestException as e:
        return {"ok": False, "error": f"Couldn't reach bridgetrail at localhost:4001 ({e}). Is the server running?"}

    if resp.status_code != 200:
        try:
            err = resp.json().get("error", resp.text)
        except ValueError:
            err = resp.text
        return {"ok": False, "error": err}

    data = resp.json()
    leaves = collect_leaves(data["root"])
    return {"ok": True, "data": data, "leaves": leaves}


def run_followup_checks(client: EtherscanClient, address: str, chain: str) -> dict:
    out = {"chainabuse": osint.check_chainabuse(address)}
    if chain in EVM_CHAINS:
        try:
            normal = client.get_normal_transactions(address, offset=1000)
            erc20 = client.get_erc20_transfers(address, offset=1000)
            out["mixer"] = {
                "ok": True,
                "tornado_hits": find_tornado_hits(normal, erc20),
                "candidates": find_mixer_candidates(address, erc20, set(), 1000.0),
            }
        except EtherscanError as e:
            out["mixer"] = {"ok": False, "error": str(e)}
    return out


def run_bridgetrail_with_followup(chain: str, tx_hash: str, max_hops: int, fan_out: int) -> dict:
    result = run_bridgetrail(chain, tx_hash, max_hops, fan_out)
    if not result["ok"]:
        return result
    client = None
    for leaf in result["leaves"]:
        if leaf.get("address"):
            if client is None:
                try:
                    client = EtherscanClient()
                except EtherscanError:
                    client = False
            leaf["followup"] = run_followup_checks(client, leaf["address"], leaf["chain"]) if client else None
    return result


# --- The unified address investigation pipeline -----------------------------

def investigate_address(address: str, known_graph: set[str], min_usd: float) -> dict:
    out: dict = {"address": address, "warnings": []}

    try:
        client = EtherscanClient()
    except EtherscanError as e:
        out["fatal_error"] = str(e)
        return out

    try:
        out["balance"] = client.get_balance(address)
        normal_txs = client.get_normal_transactions(address, offset=1000)
        erc20_txs = client.get_erc20_transfers(address, offset=1000)
    except EtherscanError as e:
        out["fatal_error"] = f"Etherscan: {e}"
        return out

    out["normal_count"] = len(normal_txs)
    out["erc20_count"] = len(erc20_txs)

    try:
        price = client.get_eth_price()
        eth_price_usd = float(price["ethusd"])
    except Exception:
        eth_price_usd = None
        out["warnings"].append("Couldn't fetch the ETH/USD price -- ETH amounts weren't converted to dollars.")

    out["chainabuse"] = osint.check_chainabuse(address)

    tornado_hits = find_tornado_hits(normal_txs, erc20_txs)
    mixer_candidates = find_mixer_candidates(address, erc20_txs, known_graph, min_usd)
    xmr_checks = []
    for c in mixer_candidates[:3]:
        if c["usd_est"] < 50_000:
            continue
        try:
            anomalies = [a for a in check_event_for_anomaly(c["timestamp"]) if a.notable]
        except Exception:
            anomalies = []
        if anomalies:
            xmr_checks.append({"candidate": c, "anomalies": anomalies})
    out["mixer"] = {"tornado_hits": tornado_hits, "candidates": mixer_candidates, "xmr_checks": xmr_checks}

    try:
        ofac = blacklists.load_ofac_addresses()
    except Exception:
        ofac = {}
        out["warnings"].append("Couldn't load the OFAC sanctions list (no network or GitHub is unavailable).")

    try:
        tether_self_frozen = blacklists.is_tether_blacklisted_now(client, address)
    except Exception:
        tether_self_frozen = False
        out["warnings"].append("Couldn't check the current freeze status in the USDT contract.")

    try:
        tether_history = blacklists.load_tether_blacklist_history(client)
    except Exception:
        tether_history = {}
        out["warnings"].append("Couldn't load the USDT freeze history.")

    try:
        scamsniffer = blacklists.load_scamsniffer_addresses()
    except Exception:
        scamsniffer = set()
        out["warnings"].append("Couldn't load the ScamSniffer blocklist.")

    chainabuse_manual = blacklists.load_chainabuse_manual()
    kristina = blacklists.load_kristina_investigations()
    third_party = blacklists.load_third_party_investigations()

    counterparties = {tx["from"].lower() for tx in normal_txs + erc20_txs} | {tx["to"].lower() for tx in normal_txs + erc20_txs}
    counterparties.discard(address.lower())
    screen = blacklists.screen_counterparties(counterparties, ofac, tether_history, scamsniffer, chainabuse_manual, kristina, third_party)

    ofac_self_name = ofac.get(address.lower())
    ofac_self_hit = {"name": ofac_self_name} if ofac_self_name else None

    goplus = external_intel.goplus_address_security(address)
    if not goplus.get("ok"):
        out["warnings"].append(f"GoPlus unavailable: {goplus.get('error')}")
    out["goplus"] = goplus

    ransomlook = external_intel.ransomlook_check("ethereum", address)
    if not ransomlook.get("ok"):
        out["warnings"].append(f"RansomLook unavailable: {ransomlook.get('error')}")
    out["ransomlook"] = ransomlook

    try:
        addr_is_contract = blacklists.is_contract(client, address)
    except Exception:
        addr_is_contract = None
        out["warnings"].append("Couldn't determine whether this is a contract or a regular address (eth_getCode).")
    out["is_contract"] = addr_is_contract

    kristina_self_hit = kristina.get(address.lower())
    out["kristina_self"] = kristina_self_hit
    third_party_self_hit = third_party.get(address.lower())
    out["third_party_self"] = third_party_self_hit

    fatf = fatf_flags.evaluate(
        address, normal_txs, erc20_txs, eth_price_usd,
        tornado_hits, ofac_self_hit, screen["ofac"],
        tether_self_frozen, screen["tether"],
        goplus.get("hits") if goplus.get("ok") else None,
        ransomlook.get("data") if ransomlook.get("ok") and ransomlook.get("found") else None,
        address.lower() in scamsniffer, screen["scamsniffer"],
        address.lower() in chainabuse_manual, screen["chainabuse_manual"],
        kristina_self_hit, screen["kristina"],
        third_party_self_hit, screen["third_party"],
        addr_is_contract,
    )
    out["fatf"] = fatf
    out["sanctions"] = screen

    transfers = fatf["transfers"]
    out["heatmap"] = timeline.build_heatmap(transfers)
    out["lifetime_note"] = timeline.wallet_lifetime_note(transfers)
    out["top_transactions"] = timeline.top_transactions(transfers)
    out["top_counterparties"] = timeline.top_counterparties(transfers)
    out["first_seen"] = min((t["timestamp"] for t in transfers), default=None)

    out["osint_web"] = osint.web_exposure(address)

    return out


def screen_local_lists(query: str) -> dict:
    """Checks an arbitrary string (TRON/Solana/BTC address, etc.) against
    all local lists -- they're just dicts/sets of strings with no chain
    binding, so they work for any address format."""
    q = blacklists.norm_address(query)
    q_eth = query.strip().lower()  # OFAC/ScamSniffer are ETH-only lists where address case doesn't matter
    hits = {}
    try:
        ofac = blacklists.load_ofac_addresses()
        if q_eth in ofac:
            hits["ofac"] = {"name": ofac[q_eth]}
    except Exception:
        pass
    try:
        if q_eth in blacklists.load_scamsniffer_addresses():
            hits["scamsniffer"] = True
    except Exception:
        pass
    if q in blacklists.load_chainabuse_manual():
        hits["chainabuse_manual"] = True
    kristina = blacklists.load_kristina_investigations()
    if q in kristina:
        hits["kristina"] = kristina[q]
    third_party = blacklists.load_third_party_investigations()
    if q in third_party:
        hits["third_party"] = third_party[q]
    return hits


@app.route("/", methods=["GET", "POST"])
def index():
    results = None
    form = {"query": "", "known_graph": "", "min_usd": "500"}

    if request.method == "POST":
        form["query"] = request.form.get("query", "").strip()
        form["known_graph"] = request.form.get("known_graph", "").strip()
        form["min_usd"] = request.form.get("min_usd", "500")

        query = form["query"]
        known_graph = {a.strip().lower() for a in form["known_graph"].split(",") if a.strip()}
        try:
            min_usd = float(form["min_usd"] or 500)
        except ValueError:
            min_usd = 500.0

        if query:
            results = {"query": query}

            if TX_HASH_RE.match(query):
                results["kind"] = "tx"
                try:
                    client = EtherscanClient()
                    tx = client.raw("proxy", "eth_getTransactionByHash", txhash=query)
                except EtherscanError as e:
                    tx = None
                    results["resolve_error"] = str(e)

                if not tx:
                    results["resolve_error"] = (
                        results.get("resolve_error")
                        or "Transaction not found on Ethereum mainnet. If it's on another chain, "
                           "enter the sender/recipient address directly, or use the bridge tracer "
                           "with a chain selector."
                    )
                else:
                    results["tx"] = tx
                    address = tx["from"]
                    results["resolved_address"] = address
                    results["bridge"] = run_bridgetrail_with_followup("ethereum", query, 5, 5)
                    results["analysis"] = investigate_address(address, known_graph, min_usd)

            elif ETH_ADDRESS_RE.match(query):
                results["kind"] = "address"
                results["analysis"] = investigate_address(query, known_graph, min_usd)

            else:
                results["kind"] = "other"
                results["chainabuse"] = osint.check_chainabuse(query)
                results["osint_web"] = osint.web_exposure(query)
                if BTC_ADDRESS_RE.match(query):
                    results["ransomlook"] = external_intel.ransomlook_check("bitcoin", query)
                results["local_lists"] = screen_local_lists(query)

    return render_template("index.html", form=form, results=results)


@app.route("/bridge", methods=["GET", "POST"])
def bridge():
    results = None
    form = {
        "chain": request.args.get("chain", "ethereum"),
        "tx_hash": request.args.get("tx_hash", "").strip(),
        "max_hops": "5", "fan_out": "5",
    }

    if request.method == "POST":
        form["chain"] = request.form.get("chain", "ethereum")
        form["tx_hash"] = request.form.get("tx_hash", "").strip()
        form["max_hops"] = request.form.get("max_hops", "5")
        form["fan_out"] = request.form.get("fan_out", "5")
        if form["tx_hash"]:
            results = run_bridgetrail_with_followup(
                form["chain"], form["tx_hash"],
                int(form["max_hops"] or 5), int(form["fan_out"] or 5),
            )
    elif form["tx_hash"]:
        results = run_bridgetrail_with_followup(form["chain"], form["tx_hash"], 5, 5)

    return render_template("bridge.html", form=form, results=results, chains=BRIDGETRAIL_CHAINS)


if __name__ == "__main__":
    ensure_bridgetrail_running()
    app.run(host="127.0.0.1", port=5055, debug=False)
