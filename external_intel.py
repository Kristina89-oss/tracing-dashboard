"""
External reputation/threat-intel sources that supplement Chainabuse (whose
free key is limited to 10 requests/month):

1. GoPlus Security Malicious Address API -- free, no key required,
   aggregates labels from GoPlus/SlowMist/BlockSec: money laundering,
   cybercrime, dark web, sanctions, theft, extortion, etc.
   https://docs.gopluslabs.io/reference/malicious-address-api

2. RansomLook -- free, no key required, a database of addresses seen on
   leak sites and in the ransom notes of ransomware gangs (the leak sites
   themselves often live on Tor -- RansomLook has already taken on that
   mirroring for us, so we don't need to touch the dark web ourselves).
   https://www.ransomlook.io/doc/
"""

from __future__ import annotations

import requests

GOPLUS_URL = "https://api.gopluslabs.io/api/v1/address_security/{address}"
RANSOMLOOK_URL = "https://www.ransomlook.io/api/crypto/addr/{chain}/{address}"

# Key -> human-readable label. Excluded: "data_source" (not a flag) and
# "contract_address" (that just means "this is a contract", not a threat
# indicator).
GOPLUS_LABELS = {
    "sanctioned": "on a sanctions list (per GoPlus)",
    "money_laundering": "money laundering",
    "financial_crime": "financial crime",
    "cybercrime": "cybercrime",
    "stealing_attack": "theft (hack/exploit)",
    "phishing_activities": "phishing",
    "blackmail_activities": "blackmail/extortion",
    "darkweb_transactions": "dark-web-linked transactions",
    "fake_kyc": "fake KYC",
    "malicious_mining_activities": "malicious mining activity",
    "honeypot_related_address": "linked to honeypot tokens",
    "fake_token": "created fake tokens",
    "fake_standard_interface": "fake standard token interface",
    "blacklist_doubt": "suspected of malicious activity",
    "reinit": "contract re-initialization (suspicious)",
    "gas_abuse": "gas abuse",
    "mixer": "mixer usage",
    "number_of_malicious_contracts_created": "created malicious contracts",
}


def goplus_address_security(address: str, chain_id: str = "1") -> dict:
    try:
        resp = requests.get(
            GOPLUS_URL.format(address=address), params={"chain_id": chain_id}, timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        return {"ok": False, "error": str(e)}

    if data.get("code") != 1:
        return {"ok": False, "error": data.get("message", "unknown GoPlus error")}

    result = data.get("result") or {}
    hits = {}
    for key, label in GOPLUS_LABELS.items():
        value = str(result.get(key, "0"))
        if value not in ("0", "", "None"):
            hits[key] = label if value == "1" else f"{label} ({value})"

    return {"ok": True, "hits": hits, "raw": result, "data_source": result.get("data_source") or ""}


def ransomlook_check(chain: str, address: str) -> dict:
    try:
        resp = requests.get(RANSOMLOOK_URL.format(chain=chain, address=address), timeout=15)
    except requests.RequestException as e:
        return {"ok": False, "error": str(e)}

    if resp.status_code == 404:
        return {"ok": True, "found": False}
    try:
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "found": True, "data": data}
