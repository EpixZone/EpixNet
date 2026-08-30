#!/usr/bin/env python3
"""Capture xid_pin.json — the cold-start trust anchor for xID finality.

Builds the pin from the chain's FULL consensus validator set at a recent
height (CometBFT RPC /validators), NOT from attestation signers: the node's
light client bootstraps by requiring the pin to EQUAL the set at the pin
height (the trust splice), so every bonded validator must be included even if
it is not currently signing vote extensions. A non-signing validator only
weighs the >2/3 denominator; it cannot block capture.

Usage:
    python3 scripts/capture_xid_pin.py [RPC_URL] [> xid_pin.json path]
Defaults to https://rpc.epix.zone and writes ./xid_pin.json.

Stdlib only. Verify the output against a SECOND independent RPC before
shipping it (the pin is the root of trust; capture is the one trusted step).
"""

import base64
import hashlib
import json
import sys
import time
import urllib.request

RPC = sys.argv[1] if len(sys.argv) > 1 else "https://rpc.epix.zone"
OUT = sys.argv[2] if len(sys.argv) > 2 else "xid_pin.json"

# --- bech32 (BIP-173) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ value
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _convertbits(data, frombits, tobits):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret


def bech32_encode(hrp, payload):
    data = _convertbits(payload, 8, 5)
    checksum = _polymod(_hrp_expand(hrp) + data + [0] * 6) ^ 1
    data += [(checksum >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data)


def rpc(path):
    with urllib.request.urlopen(f"{RPC}{path}", timeout=20) as resp:
        return json.load(resp)["result"]


def main():
    head = int(rpc("/status")["sync_info"]["latest_block_height"])
    height = head - 3  # a settled height whose next-set also exists
    header = rpc(f"/commit?height={height}")["signed_header"]["header"]
    chain_id = header["chain_id"]

    validators = []
    page = 1
    while True:
        result = rpc(f"/validators?height={height}&per_page=100&page={page}")
        for v in result["validators"]:
            addr = bytes.fromhex(v["address"])
            pubkey = base64.b64decode(v["pub_key"]["value"])
            # CometBFT invariant the light client also relies on.
            assert addr == hashlib.sha256(pubkey).digest()[:20], v["address"]
            validators.append(
                {
                    "valcons": bech32_encode("epixvalcons", addr),
                    "pubkey": pubkey.hex(),
                    "voting_power": int(v["voting_power"]),
                }
            )
        if len(validators) >= int(result["total"]):
            break
        page += 1

    pin = {
        "chain_id": chain_id,
        "pinned_at_height": height,
        "pinned_at_unix": int(time.time()),
        "validators": validators,
    }
    with open(OUT, "w") as f:
        json.dump(pin, f, indent=2)
        f.write("\n")
    total = sum(v["voting_power"] for v in validators)
    print(
        f"captured {len(validators)} validators (total power {total}) "
        f"at height {height} on {chain_id} -> {OUT}"
    )
    print("verify against a second independent RPC before shipping.")


if __name__ == "__main__":
    main()
