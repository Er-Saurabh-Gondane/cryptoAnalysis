"""
Base class for all lightweight cryptographic algorithms
"""

from abc import ABC, abstractmethod
from typing import Union, Optional
import time
import psutil


class BaseCipher(ABC):
    """Abstract base class for all cipher implementations"""

    def __init__(self, name: str, block_size: int, key_size: int):
        self.name = name
        self.block_size = block_size   # in bits
        self.key_size = key_size       # in bits
        self.round_keys = None

    @abstractmethod
    def key_schedule(self, key: Union[int, bytes, list]):
        """Generate round keys from master key"""
        pass

    @abstractmethod
    def encrypt_block(self, plaintext: Union[int, bytes, list]) -> int:
        """Encrypt a single block and return integer ciphertext"""
        pass

    @abstractmethod
    def decrypt_block(self, ciphertext: Union[int, bytes, list]) -> int:
        """Decrypt a single block and return integer plaintext"""
        pass

    def encrypt(self, data: Union[int, bytes, list], mode: str = "ecb", **kwargs) -> Union[int, bytes]:
        """
        Encrypt data.
        - int   -> single block encryption
        - bytes -> multi-block encryption with PKCS-style padding
        - list  -> converted to bytes first
        
        Args:
            data: Data to encrypt
            mode: Encryption mode ('ecb' only for now)
            **kwargs: Additional cipher-specific parameters (e.g., nonce for TinyJambu)
        """
        # Ensure mode is a string
        if not isinstance(mode, str):
            mode = "ecb"
            
        if mode.lower() != "ecb":
            raise NotImplementedError("Only ECB mode is currently supported")

        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        # Handle TinyJambu's nonce parameter
        if "TinyJambu" in self.name and kwargs.get('nonce') is not None:
            # This will be handled by the subclass
            pass

        if isinstance(data, int):
            return self.encrypt_block(data)

        if isinstance(data, list):
            data = bytes(data)

        if isinstance(data, bytes):
            block_bytes = self.block_size // 8

            # PKCS-style padding
            padding_len = block_bytes - (len(data) % block_bytes)
            if padding_len == 0:
                padding_len = block_bytes
            data += bytes([padding_len] * padding_len)

            result = bytearray()

            for i in range(0, len(data), block_bytes):
                block = data[i:i + block_bytes]
                # For block ciphers, convert bytes to int
                block_int = int.from_bytes(block, byteorder="big")
                encrypted = self.encrypt_block(block_int)
                result.extend(encrypted.to_bytes(block_bytes, byteorder="big"))

            return bytes(result)

        raise TypeError("Unsupported data type")

    def decrypt(self, data: Union[int, bytes, list], mode: str = "ecb", **kwargs) -> Union[int, bytes]:
        """
        Decrypt data.
        - int   -> single block decryption
        - bytes -> multi-block decryption and padding removal
        - list  -> converted to bytes first
        
        Args:
            data: Data to decrypt
            mode: Decryption mode ('ecb' only for now)
            **kwargs: Additional cipher-specific parameters (e.g., nonce for TinyJambu)
        """
        # Ensure mode is a string
        if not isinstance(mode, str):
            mode = "ecb"
            
        if mode.lower() != "ecb":
            raise NotImplementedError("Only ECB mode is currently supported")

        if self.round_keys is None:
            raise ValueError("Key not set. Call key_schedule() first.")

        if isinstance(data, int):
            return self.decrypt_block(data)

        if isinstance(data, list):
            data = bytes(data)

        if isinstance(data, bytes):
            block_bytes = self.block_size // 8

            if len(data) % block_bytes != 0:
                raise ValueError("Ciphertext length must be a multiple of block size")

            result = bytearray()

            for i in range(0, len(data), block_bytes):
                block = data[i:i + block_bytes]
                # For block ciphers, convert bytes to int
                block_int = int.from_bytes(block, byteorder="big")
                decrypted = self.decrypt_block(block_int)
                result.extend(decrypted.to_bytes(block_bytes, byteorder="big"))

            # Remove valid PKCS-style padding
            if len(result) > 0:
                padding_len = result[-1]
                if 1 <= padding_len <= block_bytes:
                    if result[-padding_len:] == bytes([padding_len] * padding_len):
                        return bytes(result[:-padding_len])

            return bytes(result)

        raise TypeError("Unsupported data type")

    def performance_metrics(self, func, *args, **kwargs):
        """Measure execution time and memory usage of a function"""
        process = psutil.Process()

        memory_before = process.memory_info().rss / (1024 * 1024)  # MB
        start_time = time.perf_counter()

        result = func(*args, **kwargs)

        end_time = time.perf_counter()
        memory_after = process.memory_info().rss / (1024 * 1024)  # MB

        return {
            "result": result,
            "execution_time_ms": (end_time - start_time) * 1000,
            "memory_usage_mb": memory_after - memory_before,
            "memory_peak_mb": max(memory_before, memory_after)
        }