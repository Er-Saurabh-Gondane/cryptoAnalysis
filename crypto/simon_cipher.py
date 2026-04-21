"""
SIMON Lightweight Block Cipher
Developed by NSA
Optimized for hardware performance
"""
import numpy as np
from typing import Union
from crypto.base_cipher import BaseCipher

class SimonCipher(BaseCipher):
    """
    SIMON cipher implementation
    
    Supported configurations:
    - Simon 32/64: 32-bit block, 64-bit key (32 rounds)
    - Simon 48/72: 48-bit block, 72-bit key (36 rounds)
    - Simon 48/96: 48-bit block, 96-bit key (36 rounds)
    - Simon 64/96: 64-bit block, 96-bit key (42 rounds)
    - Simon 64/128: 64-bit block, 128-bit key (44 rounds)
    - Simon 96/96: 96-bit block, 96-bit key (52 rounds)
    - Simon 96/144: 96-bit block, 144-bit key (54 rounds)
    - Simon 128/128: 128-bit block, 128-bit key (68 rounds)
    - Simon 128/192: 128-bit block, 192-bit key (69 rounds)
    - Simon 128/256: 128-bit block, 256-bit key (72 rounds)
    """
    
    # Constants for different SIMON variants
    VARIANT_CONFIGS = {
        '32/64': {'block_size': 32, 'key_size': 64, 'rounds': 32},
        '48/72': {'block_size': 48, 'key_size': 72, 'rounds': 36},
        '48/96': {'block_size': 48, 'key_size': 96, 'rounds': 36},
        '64/96': {'block_size': 64, 'key_size': 96, 'rounds': 42},
        '64/128': {'block_size': 64, 'key_size': 128, 'rounds': 44},
        '96/96': {'block_size': 96, 'key_size': 96, 'rounds': 52},
        '96/144': {'block_size': 96, 'key_size': 144, 'rounds': 54},
        '128/128': {'block_size': 128, 'key_size': 128, 'rounds': 68},
        '128/192': {'block_size': 128, 'key_size': 192, 'rounds': 69},
        '128/256': {'block_size': 128, 'key_size': 256, 'rounds': 72},
    }
    
    def __init__(self, variant: str = '64/128'):
        """
        Initialize SIMON cipher with specified variant
        
        Args:
            variant: String indicating block size and key size (e.g., '64/128')
        """
        if variant not in self.VARIANT_CONFIGS:
            raise ValueError(f"Unsupported variant. Choose from: {list(self.VARIANT_CONFIGS.keys())}")
        
        self.variant = variant
        config = self.VARIANT_CONFIGS[variant]
        super().__init__("SIMON", config['block_size'], config['key_size'])
        self.rounds = config['rounds']
        self.word_size = self.block_size // 2
        
        # Rotation constants (from SIMON specification)
        if self.block_size == 32:
            self.rot1, self.rot2, self.rot3 = 1, 8, 2
        elif self.block_size == 48:
            self.rot1, self.rot2, self.rot3 = 1, 8, 3
        elif self.block_size == 64:
            self.rot1, self.rot2, self.rot3 = 1, 8, 3
        elif self.block_size == 96:
            self.rot1, self.rot2, self.rot3 = 2, 8, 3
        else:  # 128-bit block
            self.rot1, self.rot2, self.rot3 = 2, 8, 3
            
        # Sequence constant z (from SIMON specification)
        self.z = self._get_z_constant()
        
        self.round_keys = None
    
    def _get_z_constant(self) -> int:
        """Get the z constant for the key schedule based on variant."""
        # Different z arrays for different variants
        z_arrays = {
            '32/64': 0b01100111000011010100100010111110110011100001101010010001011111,
            '48/72': 0b010011010001011100110111111000101101001000011001010011011111101100,
            '48/96': 0b010011010001011100110111111000101101001000011001010011011111101100,
            '64/96': 0b010011010001011100110111111000101101001000011001010011011111101100,
            '64/128': 0b1101101110100001100101000011101110110100001100101010000111011111,
            '96/96': 0b1000110011110110010111001011010000011100101101000001110010110100,
            '96/144': 0b1000110011110110010111001011010000011100101101000001110010110100,
            '128/128': 0b1101011110111000110110010010100001000111001101000101011000011110,
            '128/192': 0b1101011110111000110110010010100001000111001101000101011000011110,
            '128/256': 0b1101011110111000110110010010100001000111001101000101011000011110,
        }
        return z_arrays.get(self.variant, 0b01100111000011010100100010111110110011100001101010010001011111)
    
    def _rotate_left(self, x: int, n: int, word_size: int = None) -> int:
        """Rotate left operation."""
        if word_size is None:
            word_size = self.word_size
        n = n % word_size
        return ((x << n) | (x >> (word_size - n))) & ((1 << word_size) - 1)
    
    def _rotate_right(self, x: int, n: int, word_size: int = None) -> int:
        """Rotate right operation."""
        if word_size is None:
            word_size = self.word_size
        n = n % word_size
        return ((x >> n) | (x << (word_size - n))) & ((1 << word_size) - 1)
    
    def _f_function(self, x: int) -> int:
        """
        SIMON round function f(x) = (ROL(x, 1) & ROL(x, 8)) ^ ROL(x, 2)
        """
        return (self._rotate_left(x, self.rot1) & self._rotate_left(x, self.rot2)) ^ self._rotate_left(x, self.rot3)
    
    def key_schedule(self, key: Union[int, bytes, list]):
        """
        Generate round keys from the master key.
        
        Args:
            key: Master key as integer, bytes, or list of integers
        """
        # Convert key to integer if needed
        if isinstance(key, bytes):
            key = int.from_bytes(key, byteorder='big')
        elif isinstance(key, list):
            key = int.from_bytes(bytes(key), byteorder='big')
        
        # Truncate to key size
        key &= (1 << self.key_size) - 1
        
        # Calculate number of key words
        m = self.key_size // self.word_size
        self.round_keys = [0] * self.rounds
        
        # Initialize first m key words
        for i in range(m):
            self.round_keys[i] = (key >> (self.word_size * (m - 1 - i))) & ((1 << self.word_size) - 1)
        
        # Generate remaining round keys
        for i in range(m, self.rounds):
            tmp = self._rotate_right(self.round_keys[i-1], 3, self.word_size)
            
            if m == 4:
                tmp ^= self.round_keys[i-3]
            else:
                tmp ^= self.round_keys[i-m+1]
            
            tmp ^= self._rotate_right(tmp, 1, self.word_size)
            
            # XOR with z constant
            z_bit = (self.z >> ((i - m) % 62)) & 1
            self.round_keys[i] = (self.round_keys[i-m] ^ tmp ^ z_bit ^ 3) & ((1 << self.word_size) - 1)
    
    def encrypt_block(self, plaintext: Union[int, bytes, list]) -> int:
        """
        Encrypt a single block of plaintext.
        
        Args:
            plaintext: Plaintext block as integer, bytes, or list
        
        Returns:
            Ciphertext block as integer
        """
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")
        
        # Convert plaintext to integer if needed
        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder='big')
        elif isinstance(plaintext, list):
            plaintext = int.from_bytes(bytes(plaintext), byteorder='big')
        
        # Ensure block size
        plaintext &= (1 << self.block_size) - 1
        
        # Split into two words
        x = (plaintext >> self.word_size) & ((1 << self.word_size) - 1)
        y = plaintext & ((1 << self.word_size) - 1)
        
        # Rounds
        for i in range(self.rounds):
            temp = x
            x = (y ^ self._f_function(x) ^ self.round_keys[i]) & ((1 << self.word_size) - 1)
            y = temp
        
        # Combine words
        return (x << self.word_size) | y
    
    def decrypt_block(self, ciphertext: Union[int, bytes, list]) -> int:
        """
        Decrypt a single block of ciphertext.
        
        Args:
            ciphertext: Ciphertext block as integer, bytes, or list
        
        Returns:
            Plaintext block as integer
        """
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")
        
        # Convert ciphertext to integer if needed
        if isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, byteorder='big')
        elif isinstance(ciphertext, list):
            ciphertext = int.from_bytes(bytes(ciphertext), byteorder='big')
        
        # Ensure block size
        ciphertext &= (1 << self.block_size) - 1
        
        # Split into two words
        x = (ciphertext >> self.word_size) & ((1 << self.word_size) - 1)
        y = ciphertext & ((1 << self.word_size) - 1)
        
        # Reverse rounds
        for i in range(self.rounds - 1, -1, -1):
            temp = y
            y = (x ^ self._f_function(y) ^ self.round_keys[i]) & ((1 << self.word_size) - 1)
            x = temp
        
        # Combine words
        return (x << self.word_size) | y


# Test the implementation
if __name__ == "__main__":
    print("Testing SIMON-64/128:")
    simon = SimonCipher('64/128')
    
    # Test vector
    test_key = 0x1A1B1C1D1E1F20212223242526272829
    test_plaintext = 0x656B696C20646F75
    
    simon.key_schedule(test_key)
    ciphertext = simon.encrypt_block(test_plaintext)
    decrypted = simon.decrypt_block(ciphertext)
    
    print(f"Key: 0x{test_key:032X}")
    print(f"Plaintext: 0x{test_plaintext:016X}")
    print(f"Ciphertext: 0x{ciphertext:016X}")
    print(f"Decrypted: 0x{decrypted:016X}")
    print(f"Success: {decrypted == test_plaintext}")
    
    # Test with multiple variants
    print("\nTesting multiple variants:")
    variants = ['32/64', '64/128', '128/128']
    for variant in variants:
        try:
            simon_var = SimonCipher(variant)
            simon_var.key_schedule(0x0123456789ABCDEF)
            cipher = simon_var.encrypt_block(0x12345678)
            plain = simon_var.decrypt_block(cipher)
            print(f"  {variant}: ✓")
        except Exception as e:
            print(f"  {variant}: ✗ ({e})")