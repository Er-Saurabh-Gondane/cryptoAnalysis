"""
PRESENT Ultra-Lightweight Block Cipher
Block size: 64 bits
Key sizes: 80 or 128 bits
Rounds: 31
"""
from typing import Union
from crypto.base_cipher import BaseCipher

class PresentCipher(BaseCipher):
    """
    PRESENT cipher implementation
    Designed for ultra-lightweight applications like RFID tags and IoT devices
    """
    
    # PRESENT S-box (4x4)
    S_BOX = [
        0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
    ]
    
    # Inverse S-box
    INV_S_BOX = [0] * 16
    for i in range(16):
        INV_S_BOX[S_BOX[i]] = i
    
    def __init__(self, key_size: int = 80):
        """
        Initialize PRESENT cipher
        
        Args:
            key_size: 80 or 128 bits
        """
        if key_size not in [80, 128]:
            raise ValueError("PRESENT supports key sizes 80 or 128 bits")
        
        super().__init__("PRESENT", 64, key_size)
        self.rounds = 31
        self.current_key = None
        
    def _s_box_layer(self, state: int) -> int:
        """Apply S-box to each 4-bit nibble"""
        result = 0
        for i in range(16):  # 64/4 = 16 nibbles
            nibble = (state >> (4 * i)) & 0xF
            result |= (self.S_BOX[nibble] << (4 * i))
        return result & 0xFFFFFFFFFFFFFFFF
    
    def _inv_s_box_layer(self, state: int) -> int:
        """Apply inverse S-box"""
        result = 0
        for i in range(16):
            nibble = (state >> (4 * i)) & 0xF
            result |= (self.INV_S_BOX[nibble] << (4 * i))
        return result & 0xFFFFFFFFFFFFFFFF
    
    def _p_box_layer(self, state: int) -> int:
        """Apply permutation layer"""
        result = 0
        for i in range(64):
            bit = (state >> i) & 1
            if bit:
                # PRESENT permutation: bit i goes to position P(i)
                # P(i) = (i * 16) mod 63 for i < 63, and 63 for i = 63
                if i < 63:
                    new_pos = (i * 16) % 63
                else:
                    new_pos = 63
                result |= (1 << new_pos)
        return result & 0xFFFFFFFFFFFFFFFF
    
    def _inv_p_box_layer(self, state: int) -> int:
        """Apply inverse permutation"""
        result = 0
        # Create inverse permutation table
        inv_p_box = [0] * 64
        for i in range(64):
            if i < 63:
                inv_p_box[(i * 16) % 63] = i
            else:
                inv_p_box[63] = 63
        
        for i in range(64):
            bit = (state >> i) & 1
            if bit:
                result |= (1 << inv_p_box[i])
        return result & 0xFFFFFFFFFFFFFFFF
    
    def _generate_round_keys_80(self, key: int):
        """Generate round keys for 80-bit key"""
        round_keys = []
        current_key = key & ((1 << 80) - 1)
        
        for i in range(1, self.rounds + 2):  # +1 to have enough keys
            # Extract round key (first 64 bits)
            round_key = (current_key >> 16) & 0xFFFFFFFFFFFFFFFF
            round_keys.append(round_key)
            
            # Rotate key left by 61 bits
            current_key = ((current_key << 61) | (current_key >> 19)) & ((1 << 80) - 1)
            
            # Apply S-box to leftmost 4 bits
            leftmost = (current_key >> 76) & 0xF
            current_key = (self.S_BOX[leftmost] << 76) | (current_key & ((1 << 76) - 1))
            
            # XOR round counter (bits 15-19)
            current_key ^= (i << 15)
        
        return round_keys[:self.rounds + 1]  # Return only needed keys
    
    def _generate_round_keys_128(self, key: int):
        """Generate round keys for 128-bit key"""
        round_keys = []
        current_key = key & ((1 << 128) - 1)
        
        for i in range(1, self.rounds + 2):  # +1 to have enough keys
            # Extract round key (first 64 bits)
            round_key = (current_key >> 64) & 0xFFFFFFFFFFFFFFFF
            round_keys.append(round_key)
            
            # Rotate key left by 61 bits
            current_key = ((current_key << 61) | (current_key >> 67)) & ((1 << 128) - 1)
            
            # Apply S-box to leftmost 8 bits (two S-box applications)
            leftmost1 = (current_key >> 124) & 0xF
            leftmost2 = (current_key >> 120) & 0xF
            new_value = (self.S_BOX[leftmost1] << 4) | self.S_BOX[leftmost2]
            current_key = (new_value << 120) | (current_key & ((1 << 120) - 1))
            
            # XOR round counter (bits 62-66)
            current_key ^= (i << 62)
        
        return round_keys[:self.rounds + 1]  # Return only needed keys
    
    def key_schedule(self, key: Union[int, bytes, list]):
        """Generate round keys from master key"""
        # Convert key to integer
        if isinstance(key, bytes):
            key = int.from_bytes(key, byteorder='big')
        elif isinstance(key, list):
            key = int.from_bytes(bytes(key), byteorder='big')
        
        # Truncate to key size
        key &= (1 << self.key_size) - 1
        self.current_key = key
        
        # Generate round keys based on key size
        if self.key_size == 80:
            self.round_keys = self._generate_round_keys_80(key)
        else:  # 128 bits
            self.round_keys = self._generate_round_keys_128(key)
    
    def encrypt_block(self, plaintext: Union[int, bytes, list]) -> int:
        """Encrypt a single 64-bit block"""
        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")
        
        # Convert plaintext to integer
        if isinstance(plaintext, bytes):
            plaintext = int.from_bytes(plaintext, byteorder='big')
        elif isinstance(plaintext, list):
            plaintext = int.from_bytes(bytes(plaintext), byteorder='big')
        
        # Ensure 64-bit block
        state = plaintext & 0xFFFFFFFFFFFFFFFF
        
        # Add round key for round 0
        state ^= self.round_keys[0]
        
        # Main rounds (1 to 30)
        for round_num in range(1, self.rounds):
            # S-box layer
            state = self._s_box_layer(state)
            # P-box layer
            state = self._p_box_layer(state)
            # Add round key
            state ^= self.round_keys[round_num]
        
        # Final round (round 31) - no P-box
        state = self._s_box_layer(state)
        state ^= self.round_keys[self.rounds]
        
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
        
        # Ensure 64-bit block
        state = ciphertext & 0xFFFFFFFFFFFFFFFF
        
        # Undo final round
        state ^= self.round_keys[self.rounds]
        state = self._inv_s_box_layer(state)
        
        # Main rounds (reverse)
        for round_num in range(self.rounds - 1, 0, -1):
            # Undo round key
            state ^= self.round_keys[round_num]
            # Undo P-box
            state = self._inv_p_box_layer(state)
            # Undo S-box
            state = self._inv_s_box_layer(state)
        
        # Undo initial key addition
        state ^= self.round_keys[0]
        
        return state & 0xFFFFFFFFFFFFFFFF