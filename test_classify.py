import unittest

from classify import classify


class ClassifyTest(unittest.TestCase):
    def assertKind(self, addr, fragment):
        kinds = classify(addr)
        self.assertTrue(any(fragment in k for k in kinds), f"{addr}: {kinds}")

    def test_evm(self):
        self.assertKind("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045", "EVM")

    def test_bitcoin_legacy(self):
        self.assertKind("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", "Bitcoin P2PKH")

    def test_bitcoin_legacy_bad_checksum(self):
        self.assertEqual(classify("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAt"), [])

    def test_segwit_and_taproot(self):
        self.assertKind("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "SegWit v0")
        self.assertKind("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "Taproot")

    def test_tron(self):
        self.assertKind("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t", "Tron")

    def test_solana(self):
        self.assertKind("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", "Solana")

    def test_cosmos(self):
        self.assertKind("cosmos1hsk6jryyqjfhp5dhc55tc9jtckygx0eph6dd02", "Cosmos")

    def test_garbage(self):
        self.assertEqual(classify("hello world"), [])


if __name__ == "__main__":
    unittest.main()
