# crypto-address-classifier

Takes a string that looks like an address and tells you which chains and address types it could
belong to.

```bash
python classify.py 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
python classify.py TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
cat list.txt | python classify.py -
```

| detected | rule |
|---|---|
| EVM (Ethereum, Base, BSC...) | `0x` + 40 hex |
| Aptos / Sui | `0x` + 64 hex |
| Bitcoin P2PKH / P2SH | Base58Check, version 0x00 / 0x05, checksum verified |
| Bitcoin SegWit / Taproot | `bc1q...` / `bc1p...` prefix and charset |
| Litecoin, Dogecoin | Base58Check versions 0x30 / 0x32, 0x1e |
| Tron | Base58Check version 0x41 |
| Solana | Base58 that decodes to exactly 32 bytes |
| Cosmos SDK chains | bech32-style `cosmos1`, `osmo1`, `celestia1` ... |

Some formats overlap. Any 32 bytes in base58 pass as a Solana address, and an EVM address is valid on
every EVM chain. The output therefore lists every plausible match.

Bech32 checksums are not verified. Use a real Bech32 decoder if you need that.

## Tests

```bash
python -m unittest -v
```
