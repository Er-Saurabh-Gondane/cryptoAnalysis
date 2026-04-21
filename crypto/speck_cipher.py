"""
SPECK Lightweight Block Cipher
Developed by NSA as a companion to SIMON
Optimized for software performance
"""

from typing import Union
from crypto.base_cipher import BaseCipher


class SpeckCipher(BaseCipher):
    """
    SPECK cipher implementation
    Supports multiple block and key sizes
    """

    VARIANTS = {
        "32/64": {"block_size": 32, "key_size": 64, "rounds": 22, "alpha": 7, "beta": 2},
        "48/72": {"block_size": 48, "key_size": 72, "rounds": 22, "alpha": 8, "beta": 3},
        "48/96": {"block_size": 48, "key_size": 96, "rounds": 23, "alpha": 8, "beta": 3},
        "64/96": {"block_size": 64, "key_size": 96, "rounds": 26, "alpha": 8, "beta": 3},
        "64/128": {"block_size": 64, "key_size": 128, "rounds": 27, "alpha": 8, "beta": 3},
        "96/96": {"block_size": 96, "key_size": 96, "rounds": 28, "alpha": 8, "beta": 3},
        "96/144": {"block_size": 96, "key_size": 144, "rounds": 29, "alpha": 8, "beta": 3},
        "128/128": {"block_size": 128, "key_size": 128, "rounds": 32, "alpha": 8, "beta": 3},
        "128/192": {"block_size": 128, "key_size": 192, "rounds": 33, "alpha": 8, "beta": 3},
        "128/256": {"block_size": 128, "key_size": 256, "rounds": 34, "alpha": 8, "beta": 3},
    }

    def __init__(self, variant: str = "64/128"):
        if variant not in self.VARIANTS:
            raise ValueError(f"Unsupported variant. Choose from: {list(self.VARIANTS.keys())}")

        self.variant = variant
        config = self.VARIANTS[variant]

        super().__init__("SPECK", config["block_size"], config["key_size"])

        self.rounds = config["rounds"]
        self.word_size = self.block_size // 2
        self.alpha = config["alpha"]
        self.beta = config["beta"]
        self.word_mask = (1 << self.word_size) - 1
        self.round_keys = None

    def _ror(self, x: int, r: int) -> int:
        r %= self.word_size
        return ((x >> r) | (x << (self.word_size - r))) & self.word_mask

    def _rol(self, x: int, r: int) -> int:
        r %= self.word_size
        return ((x << r) | (x >> (self.word_size - r))) & self.word_mask

    def _round(self, x: int, y: int, k: int) -> tuple[int, int]:
        """One round of SPECK encryption"""
        x = (self._ror(x, self.alpha) + y) & self.word_mask
        x ^= k
        y = self._rol(y, self.beta) ^ x
        return x, y

    def _inv_round(self, x: int, y: int, k: int) -> tuple[int, int]:
        """One round of SPECK decryption"""
        y = self._ror(y ^ x, self.beta)
        x = ((x ^ k) - y) & self.word_mask
        x = self._rol(x, self.alpha)
        return x, y

    def key_schedule(self, key: Union[int, bytes, list]):
        """Generate round keys from master key"""
        if isinstance(key, bytes):
            key = int.from_bytes(key, byteorder="little")
        elif isinstance(key, list):
            key = int.from_bytes(bytes(key), byteorder="little")

        key &= (1 << self.key_size) - 1

        m = self.key_size // self.word_size

        # Split into key words in little-endian order
        key_words = [
            (key >> (self.word_size * i)) & self.word_mask
            for i in range(m)
        ]

        # According to SPECK key schedule:
        # k[0] is the first round key, rest go to l[]
        self.round_keys = [0] * self.rounds
        self.round_keys[0] = key_words[0]
        l = key_words[1:]

        for i in range(self.rounds - 1):
            li = l[i]
            ki = self.round_keys[i]

            new_l = (self._ror(li, self.alpha) + ki) & self.word_mask
            new_l ^= i
            l.append(new_l)

            new_k = self._rol(ki, self.beta) ^ new_l
            self.round_keys[i + 1] = new_k

    def encrypt_block(self, plaintext: Union[int, bytes, list]) -> int:
        """Encrypt a single block"""
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder="little")
        elif isinstance(plaintext, list):
            plaintext = int.from_bytes(bytes(plaintext), byteorder="little")

        plaintext &= (1 << self.block_size) - 1

        x = plaintext & self.word_mask
        y = (plaintext >> self.word_size) & self.word_mask

        for i in range(self.rounds):
            x, y = self._round(x, y, self.round_keys[i])

        return (y << self.word_size) | x

    def decrypt_block(self, ciphertext: Union[int, bytes, list]) -> int:
        """Decrypt a single block"""
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        if isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, byteorder="little")
        elif isinstance(ciphertext, list):
            ciphertext = int.from_bytes(bytes(ciphertext), byteorder="little")

        ciphertext &= (1 << self.block_size) - 1

        x = ciphertext & self.word_mask
        y = (ciphertext >> self.word_size) & self.word_mask

        for i in range(self.rounds - 1, -1, -1):
            x, y = self._inv_round(x, y, self.round_keys[i])

        return (y << self.word_size) | x


if __name__ == "__main__":
    print("=" * 60)
    print("SPECK Cipher Test")
    print("=" * 60)

    # Official test vector for SPECK-64/128
    # key = 0x0f0e0d0c0b0a09080706050403020100
    # plaintext = 0x6c61766975716520
    # ciphertext = 0xa65d985179783265

    speck = SpeckCipher("64/128")
    test_key = 0x0f0e0d0c0b0a09080706050403020100
    test_plaintext = 0x6c61766975716520
    expected_cipher = 0xa65d985179783265

    print("Testing SPECK-64/128 official vector")
    print(f"Key               : 0x{test_key:032x}")
    print(f"Plaintext         : 0x{test_plaintext:016x}")
    print(f"Expected Cipher   : 0x{expected_cipher:016x}")

    speck.key_schedule(test_key)
    ciphertext = speck.encrypt_block(test_plaintext)
    decrypted = speck.decrypt_block(ciphertext)

    print(f"Actual Cipher     : 0x{ciphertext:016x}")
    print(f"Decrypted         : 0x{decrypted:016x}")
    print(f"Matches expected  : {ciphertext == expected_cipher}")
    print(f"Encrypt/Decrypt OK: {decrypted == test_plaintext}")

    print("\n" + "=" * 60)
    print("Testing multiple variants")
    print("=" * 60)

    test_variants = ["32/64", "48/72", "64/128", "128/128"]

    for variant in test_variants:
        try:
            sp = SpeckCipher(variant)

            if variant == "32/64":
                key = 0x1918111009080100
                pt = 0x6574694c
            elif variant == "48/72":
                key = 0x1211100a0908020100
                pt = 0x20796c6c6172
            elif variant == "64/128":
                key = 0x0f0e0d0c0b0a09080706050403020100
                pt = 0x6c61766975716520
            elif variant == "128/128":
                key = 0x0f0e0d0c0b0a09080706050403020100
                pt = 0x6c617669757165207469206564616d20

            sp.key_schedule(key)
            ct = sp.encrypt_block(pt)
            dt = sp.decrypt_block(ct)

            success = dt == pt
            status = "✓" if success else "✗"
            print(f"{status} {variant}: Block={sp.block_size} bits, Key={sp.key_size} bits, Rounds={sp.rounds}")

        except Exception as e:
            print(f"✗ {variant}: Error - {e}")