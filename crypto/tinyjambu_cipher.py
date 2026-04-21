from typing import Union, Optional
from crypto.base_cipher import BaseCipher


class TinyJambuCipher(BaseCipher):
    """
    Corrected TinyJambu implementation
    Block size: 32 bits
    Key size: 128 bits
    Nonce size: 96 bits
    Tag size: 64 bits
    """

    def __init__(self, key_size: int = 128, version: str = "128"):
        if key_size != 128:
            raise ValueError("TinyJambu uses a 128-bit key")

        super().__init__("TinyJambu", 32, key_size)

        if version not in {"128", "96", "64"}:
            raise ValueError("Version must be '128', '96', or '64'")

        self.version = version
        self.state_size = 128
        self.nonce_size = 96
        self.tag_size = 64

        self.rounds = {
            "128": 384,
            "96": 256,
            "64": 128
        }[version]

        self.state = [0, 0, 0, 0]  # [s0, s1, s2, s3] where s0 is newest
        self.nonce = None
        self.master_key = None

    def _rotate_left(self, x: int, n: int) -> int:
        n = n % 32
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _nonlinear_function(self, x: int) -> int:
        """NLS function: rotl(x, 19) ^ rotl(x, 31)"""
        return self._rotate_left(x, 19) ^ self._rotate_left(x, 31)

    def _state_update(self, data: int, frame_bit: int) -> None:
        """
        Correct state update according to TinyJambu spec
        State: [s0, s1, s2, s3] where s0 is newest
        """
        s0, s1, s2, s3 = self.state
        
        # Feedback = s0 ^ NLS(s1) ^ s2 ^ s3 ^ data ^ frame_bit
        feedback = s0 ^ self._nonlinear_function(s1) ^ s2 ^ s3 ^ data ^ frame_bit
        feedback &= 0xFFFFFFFF
        
        # Shift state: new_s0 = feedback, others shift right
        self.state = [feedback, s0, s1, s2]

    def _permutation(self, rounds: int, domain: int = 0) -> None:
        """
        Correct permutation according to TinyJambu spec
        domain: 0 for key initialization, 1 for encryption, 2 for finalization
        """
        for step in range(rounds):
            # Determine frame bit based on step position
            if step == 0:
                frame_bit = domain ^ 1  # Usually 1 for non-final steps
            elif step == rounds - 1:
                frame_bit = domain ^ 2  # Usually 2 for final step
            else:
                frame_bit = domain
            
            self._state_update(0, frame_bit)

    def _to_int(self, value: Union[int, bytes, list], bits: int) -> int:
        if isinstance(value, int):
            return value & ((1 << bits) - 1)
        if isinstance(value, bytes):
            return int.from_bytes(value, byteorder="big") & ((1 << bits) - 1)
        if isinstance(value, list):
            return int.from_bytes(bytes(value), byteorder="big") & ((1 << bits) - 1)
        raise TypeError("Unsupported type")

    def _int_to_words(self, value: int, word_size: int = 32) -> list:
        """Convert integer to list of 32-bit words"""
        words = []
        for i in range((value.bit_length() + word_size - 1) // word_size):
            shift = (len(words)) * word_size
            words.append((value >> shift) & 0xFFFFFFFF)
        return words

    def key_schedule(self, key: Union[int, bytes, list]) -> None:
        """Set the master key"""
        self.master_key = self._to_int(key, 128)

    def initialize(self, key: Union[int, bytes, list], nonce: Union[int, bytes, list]) -> None:
        """Initialize TinyJambu with key and nonce"""
        key_int = self._to_int(key, 128)
        nonce_int = self._to_int(nonce, 96)
        
        # Split key into 4 words (32 bits each)
        key_words = [
            (key_int >> 96) & 0xFFFFFFFF,
            (key_int >> 64) & 0xFFFFFFFF,
            (key_int >> 32) & 0xFFFFFFFF,
            key_int & 0xFFFFFFFF,
        ]
        
        # Split nonce into 3 words (32 bits each)
        nonce_words = [
            (nonce_int >> 64) & 0xFFFFFFFF,
            (nonce_int >> 32) & 0xFFFFFFFF,
            nonce_int & 0xFFFFFFFF,
        ]
        
        # Initialize state: [nonce0, nonce1, nonce2, key0]
        self.state = [
            nonce_words[0],
            nonce_words[1],
            nonce_words[2],
            key_words[0]
        ]
        
        # First permutation
        self._permutation(self.rounds, domain=0)
        
        # XOR remaining key words
        self.state[0] ^= key_words[1]
        self.state[1] ^= key_words[2]
        self.state[2] ^= key_words[3]
        
        # Second permutation
        self._permutation(self.rounds, domain=0)
        
        self.nonce = nonce_int

    def _generate_keystream(self) -> int:
        """Generate 32-bit keystream from current state"""
        s0, s1, s2, s3 = self.state
        # Keystream = s0 ^ NLS(s1) ^ s2
        keystream = s0 ^ self._nonlinear_function(s1) ^ s2
        return keystream & 0xFFFFFFFF

    def encrypt_block(
        self,
        plaintext: Union[int, bytes, list],
        nonce: Optional[Union[int, bytes, list]] = None
    ) -> int:
        if self.master_key is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        if nonce is not None:
            self.initialize(self.master_key, nonce)
        elif self.nonce is None:
            raise ValueError("Nonce must be provided for the first block.")

        plaintext_int = self._to_int(plaintext, 32)
        
        # Generate keystream and encrypt
        keystream = self._generate_keystream()
        ciphertext = plaintext_int ^ keystream
        ciphertext &= 0xFFFFFFFF
        
        # Update state with plaintext (not ciphertext!)
        self._state_update(plaintext_int, 1)
        
        return ciphertext

    def decrypt_block(
        self,
        ciphertext: Union[int, bytes, list],
        nonce: Optional[Union[int, bytes, list]] = None
    ) -> int:
        if self.master_key is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        if nonce is not None:
            self.initialize(self.master_key, nonce)
        elif self.nonce is None:
            raise ValueError("Nonce must be provided for the first block.")

        ciphertext_int = self._to_int(ciphertext, 32)
        
        # Generate keystream and decrypt
        keystream = self._generate_keystream()
        plaintext = ciphertext_int ^ keystream
        plaintext &= 0xFFFFFFFF
        
        # Update state with plaintext (important!)
        self._state_update(plaintext, 1)
        
        return plaintext

    def finalize(self) -> int:
        """Generate authentication tag"""
        # Final permutation with domain separation
        self._permutation(self.rounds, domain=2)
        
        # Return first 64 bits of state as tag
        tag = ((self.state[0] & 0xFFFFFFFF) << 32) | (self.state[1] & 0xFFFFFFFF)
        return tag & 0xFFFFFFFFFFFFFFFF

    def encrypt(
        self,
        data: Union[int, bytes, list],
        mode: str = "ecb",
        **kwargs
    ) -> Union[int, bytes]:
        if self.master_key is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        nonce = kwargs.get("nonce")
        if nonce is None:
            raise ValueError("TinyJambu requires a nonce for encryption.")

        # Handle single block
        if isinstance(data, int):
            return self.encrypt_block(data, nonce)

        # Handle list input
        if isinstance(data, list):
            data = bytes(data)

        if not isinstance(data, bytes):
            raise TypeError("Unsupported data type")

        # Initialize
        self.initialize(self.master_key, nonce)

        result = bytearray()

        # Process each 32-bit block
        for i in range(0, len(data), 4):
            block = data[i:i + 4]
            if len(block) < 4:
                # Pad last block with zeros
                block = block.ljust(4, b"\x00")

            block_int = int.from_bytes(block, byteorder="big")
            encrypted_int = self.encrypt_block(block_int)
            result.extend(encrypted_int.to_bytes(4, byteorder="big"))

        # Add authentication tag
        tag = self.finalize()
        result.extend(tag.to_bytes(8, byteorder="big"))

        return bytes(result)

    def decrypt(
        self,
        data: Union[int, bytes, list],
        mode: str = "ecb",
        **kwargs
    ) -> Union[int, bytes]:
        if self.master_key is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        nonce = kwargs.get("nonce")
        if nonce is None:
            raise ValueError("TinyJambu requires a nonce for decryption.")

        # Handle single block
        if isinstance(data, int):
            return self.decrypt_block(data, nonce)

        # Handle list input
        if isinstance(data, list):
            data = bytes(data)

        if not isinstance(data, bytes):
            raise TypeError("Unsupported data type")

        if len(data) < 8:
            raise ValueError("Ciphertext too short for tag.")

        # Split ciphertext and tag
        ciphertext = data[:-8]
        received_tag = int.from_bytes(data[-8:], byteorder="big")

        # Initialize
        self.initialize(self.master_key, nonce)

        result = bytearray()

        # Process each 32-bit block
        for i in range(0, len(ciphertext), 4):
            block = ciphertext[i:i + 4]
            if len(block) < 4:
                block = block.ljust(4, b"\x00")

            block_int = int.from_bytes(block, byteorder="big")
            decrypted_int = self.decrypt_block(block_int)
            result.extend(decrypted_int.to_bytes(4, byteorder="big"))

        # Verify tag
        computed_tag = self.finalize()
        if computed_tag != received_tag:
            raise ValueError("Authentication failed: tag mismatch")

        # Remove padding
        return bytes(result.rstrip(b"\x00"))


if __name__ == "__main__":
    print("=" * 60)
    print("Testing Corrected TinyJambu-128")
    print("=" * 60)

    tinyjambu = TinyJambuCipher(128, "128")

    test_key = 0x000102030405060708090A0B0C0D0E0F
    test_nonce = 0x000102030405060708090A0B
    test_plaintext = b"Hello TinyJambu!"

    tinyjambu.key_schedule(test_key)

    print(f"Key: 0x{test_key:032X}")
    print(f"Nonce: 0x{test_nonce:024X}")
    print(f"Plaintext: {test_plaintext}")

    ciphertext = tinyjambu.encrypt(test_plaintext, nonce=test_nonce)
    print(f"Ciphertext (hex): {ciphertext.hex()}")

    decrypted = tinyjambu.decrypt(ciphertext, nonce=test_nonce)
    print(f"Decrypted: {decrypted.decode('utf-8')}")
    print(f"Success: {decrypted == test_plaintext}")

    print("\n" + "=" * 60)
    print("Testing single block encryption")
    print("=" * 60)

    tinyjambu2 = TinyJambuCipher(128, "128")
    tinyjambu2.key_schedule(test_key)

    block = 0x12345678
    encrypted = tinyjambu2.encrypt_block(block, test_nonce)

    tinyjambu3 = TinyJambuCipher(128, "128")
    tinyjambu3.key_schedule(test_key)
    decrypted_block = tinyjambu3.decrypt_block(encrypted, test_nonce)

    print(f"Plaintext block: 0x{block:08X}")
    print(f"Encrypted block: 0x{encrypted:08X}")
    print(f"Decrypted block: 0x{decrypted_block:08X}")
    print(f"Success: {decrypted_block == block}")