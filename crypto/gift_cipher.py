"""
GIFT Lightweight Block Cipher
GIFT is a lightweight block cipher based on the PRESENT design
Block size: 64 bits
Key size: 128 bits
Rounds: 28
"""
from typing import Union
from crypto.base_cipher import BaseCipher

class GiftCipher(BaseCipher):
    """
    GIFT cipher implementation (GIFT-64/128)
    Improved version of PRESENT with better security and performance
    """
    
    # GIFT S-box (4x4)
    S_BOX = [
        0x1, 0xa, 0x4, 0xc, 0x6, 0xf, 0x3, 0x9,
        0x2, 0xd, 0xb, 0x7, 0x5, 0x0, 0x8, 0xe
    ]
    
    # Inverse S-box
    INV_S_BOX = [0] * 16
    for i in range(16):
        INV_S_BOX[S_BOX[i]] = i
    
    # Bit permutation for GIFT
    P_BOX = [
        0, 17, 34, 51, 48, 1, 18, 35, 32, 49, 2, 19, 16, 33, 50, 3,
        4, 21, 38, 55, 52, 5, 22, 39, 36, 53, 6, 23, 20, 37, 54, 7,
        8, 25, 42, 59, 56, 9, 26, 43, 40, 57, 10, 27, 24, 41, 58, 11,
        12, 29, 46, 63, 60, 13, 30, 47, 44, 61, 14, 31, 28, 45, 62, 15
    ]
    
    # Round constants (for 28 rounds)
    ROUND_CONSTANTS = [
        0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3D, 0x3B, 0x37,
        0x2F, 0x1F, 0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1F,
        0x3E, 0x3D, 0x3B, 0x37, 0x2F, 0x1F, 0x3E, 0x3D,
        0x3B, 0x37, 0x2F, 0x1F
    ]
    
    def __init__(self):
        """Initialize GIFT-64/128 cipher"""
        super().__init__("GIFT", 64, 128)
        self.rounds = 28
    
    def _s_box_layer(self, state: int) -> int:
        """Apply S-box to each 4-bit nibble"""
        result = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            result |= (self.S_BOX[nibble] << (4 * i))
        return result
    
    def _inv_s_box_layer(self, state: int) -> int:
        """Apply inverse S-box"""
        result = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            result |= (self.INV_S_BOX[nibble] << (4 * i))
        return result
    
    def _p_box_layer(self, state: int) -> int:
        """Apply GIFT permutation"""
        result = 0
        for i in range(64):
            bit = (state >> i) & 1
            if bit:
                result |= (1 << self.P_BOX[i])
        return result
    
    def _inv_p_box_layer(self, state: int) -> int:
        """Apply inverse permutation"""
        result = 0
        inv_p_box = [0] * 64
        for i in range(64):
            inv_p_box[self.P_BOX[i]] = i
        
        for i in range(64):
            bit = (state >> i) & 1
            if bit:
                result |= (1 << inv_p_box[i])
        return result
    
    def key_schedule(self, key: Union[int, bytes, list]):
        """Generate round keys for GIFT"""
        # Convert key to integer
        if isinstance(key, bytes):
            key = int.from_bytes(key, byteorder='big')
        elif isinstance(key, list):
            key = int.from_bytes(bytes(key), byteorder='big')
        
        # Truncate to 128 bits
        key &= 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        
        # Split key into two 64-bit halves
        k1 = (key >> 64) & 0xFFFFFFFFFFFFFFFF
        k2 = key & 0xFFFFFFFFFFFFFFFF
        
        self.round_keys = []
        
        # Generate round keys for each round
        U = [0] * 4
        V = [0] * 4
        
        for r in range(self.rounds):
            # Extract round key from k1 and k2
            round_key = (k1 & 0xFFFFFFF800000000) | ((k2 >> 32) & 0xFFFFFFFF)
            self.round_keys.append(round_key)
            
            # Update k1 and k2
            for i in range(4):
                U[i] = k1 & 0xF
                k1 >>= 4
                V[i] = k2 & 0xF
                k2 >>= 4
            
            # Key state update
            k1 = (k1 << 48) | (V[3] << 44) | (V[2] << 40) | (V[1] << 36) | (V[0] << 32) | \
                 (U[3] << 28) | (U[2] << 24) | (U[1] << 20) | (U[0] << 16)
            k2 = (k2 << 48)
            
            # Apply round constant to k1
            k1 ^= (self.ROUND_CONSTANTS[r] << 60)
    
    def encrypt_block(self, plaintext: Union[int, bytes, list]) -> int:
        """Encrypt a single 64-bit block"""
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")
        
        # Convert plaintext to integer
        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder='big')
        elif isinstance(plaintext, list):
            plaintext = int.from_bytes(bytes(plaintext), byteorder='big')
        
        state = plaintext & 0xFFFFFFFFFFFFFFFF
        
        # Encryption rounds
        for r in range(self.rounds):
            # Add round key
            state ^= self.round_keys[r]
            
            # S-box layer
            state = self._s_box_layer(state)
            
            # Permutation layer
            state = self._p_box_layer(state)
        
        return state & 0xFFFFFFFFFFFFFFFF
    
    def decrypt_block(self, ciphertext: Union[int, bytes, list]) -> int:
        """Decrypt a single 64-bit block"""
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")
        
        # Convert ciphertext to integer
        if isinstance(ciphertext, bytes):
            ciphertext = int.from_bytes(ciphertext, byteorder='big')
        elif isinstance(ciphertext, list):
            ciphertext = int.from_bytes(bytes(ciphertext), byteorder='big')
        
        state = ciphertext & 0xFFFFFFFFFFFFFFFF
        
        # Decryption rounds (reverse order)
        for r in range(self.rounds - 1, -1, -1):
            # Inverse permutation
            state = self._inv_p_box_layer(state)
            
            # Inverse S-box
            state = self._inv_s_box_layer(state)
            
            # Add round key
            state ^= self.round_keys[r]
        
        return state & 0xFFFFFFFFFFFFFFFF


# Test the implementation
if __name__ == "__main__":
    print("Testing GIFT-64/128:")
    gift = GiftCipher()
    
    # Test vector
    test_key = 0x00000000000000000000000000000000
    test_plaintext = 0x0000000000000000
    
    gift.key_schedule(test_key)
    ciphertext = gift.encrypt_block(test_plaintext)
    decrypted = gift.decrypt_block(ciphertext)
    
    print(f"Key: 0x{test_key:032X}")
    print(f"Plaintext: 0x{test_plaintext:016X}")
    print(f"Ciphertext: 0x{ciphertext:016X}")
    print(f"Decrypted: 0x{decrypted:016X}")
    print(f"Success: {decrypted == test_plaintext}")