"""Guess the chain and type of a crypto address."""
import hashlib
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARS = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BASE58CHECK_VERSIONS = {
    0x00: "Bitcoin P2PKH", 0x05: "Bitcoin P2SH", 0x30: "Litecoin P2PKH",
    0x32: "Litecoin P2SH", 0x1E: "Dogecoin P2PKH", 0x16: "Dogecoin P2SH", 0x41: "Tron",
}
BECH32_HRPS = {
    "bc": "Bitcoin", "tb": "Bitcoin testnet", "ltc": "Litecoin", "cosmos": "Cosmos Hub",
    "osmo": "Osmosis", "celestia": "Celestia", "inj": "Injective", "sei": "Sei", "dydx": "dYdX",
}


def b58decode(s: str) -> bytes | None:
    n = 0
    for c in s:
        i = B58.find(c)
        if i < 0:
            return None
        n = n * 58 + i
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


def base58check_kind(s: str) -> str | None:
    raw = b58decode(s)
    if raw is None or len(raw) != 25:
        return None
    payload, chk = raw[:-4], raw[-4:]
    if hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] != chk:
        return None
    return BASE58CHECK_VERSIONS.get(payload[0])


def classify(addr: str) -> list[str]:
    a = addr.strip()
    out = []
    if re.fullmatch(r"0x[0-9a-fA-F]{40}", a):
        out.append("EVM address")
    if re.fullmatch(r"0x[0-9a-fA-F]{64}", a):
        out.append("Aptos / Sui address")
    kind = base58check_kind(a)
    if kind:
        out.append(kind)
    low = a.lower()
    if "1" in low and (low == a or a.upper() == a):
        hrp, _, data = low.rpartition("1")
        if hrp in BECH32_HRPS and data and all(c in BECH32_CHARS for c in data):
            name = BECH32_HRPS[hrp]
            if hrp in ("bc", "tb", "ltc"):
                name += " Taproot" if data[0] == "p" else " SegWit v0" if data[0] == "q" else " SegWit"
            out.append(name + " (bech32, checksum not verified)")
    if not kind and 32 <= len(a) <= 44:
        raw = b58decode(a)
        if raw is not None and len(raw) == 32:
            out.append("Solana address (32-byte public key)")
    return out


def main():
    items = sys.argv[1:]
    if items == ["-"]:
        items = [line.strip() for line in sys.stdin if line.strip()]
    if not items:
        sys.exit("usage: classify.py ADDRESS [...]  or  classify.py -")
    for a in items:
        kinds = classify(a)
        print(f"{a}\n    {' | '.join(kinds) if kinds else 'unknown'}")


if __name__ == "__main__":
    main()
