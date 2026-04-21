"""
Test script for all lightweight cryptographic algorithms
"""

import sys
import os
import time
import psutil

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from crypto.present_cipher import PresentCipher
from crypto.simon_cipher import SimonCipher
from crypto.speck_cipher import SpeckCipher
from crypto.gift_cipher import GiftCipher
from crypto.tinyjambu_cipher import TinyJambuCipher


def test_cipher(cipher, name, test_data):
    """Test a single cipher and measure performance"""
    print(f"\n{'=' * 60}")
    print(f"Testing {name}")
    print(f"{'=' * 60}")

    if "TinyJambu" in name:
        key = 0x000102030405060708090A0B0C0D0E0F
        nonce = 0x000102030405060708090A0B
        cipher.key_schedule(key)

        start_time = time.perf_counter()
        cpu_before = psutil.cpu_percent(interval=None)
        mem_before = psutil.Process().memory_info().rss / 1024 / 1024

        ciphertext = cipher.encrypt_block(test_data, nonce)

        cpu_after = psutil.cpu_percent(interval=None)
        mem_after = psutil.Process().memory_info().rss / 1024 / 1024
        enc_time = time.perf_counter() - start_time

        tag = cipher.finalize()

        cipher2 = TinyJambuCipher(128, '128')
        cipher2.key_schedule(key)
        decrypted = cipher2.decrypt_block(ciphertext, nonce)
        verify_tag = cipher2.finalize()

    else:
        if cipher.key_size == 80:
            key = 0x0123456789ABCDEF0123
        elif cipher.key_size == 128:
            key = 0x0123456789ABCDEF0123456789ABCDEF
        else:
            key = 0x0123456789ABCDEF0123456789ABCDEF

        cipher.key_schedule(key)

        start_time = time.perf_counter()
        cpu_before = psutil.cpu_percent(interval=None)
        mem_before = psutil.Process().memory_info().rss / 1024 / 1024

        if cipher.block_size == 32:
            test_block = test_data & 0xFFFFFFFF
        else:
            test_block = test_data

        ciphertext = cipher.encrypt_block(test_block)

        cpu_after = psutil.cpu_percent(interval=None)
        mem_after = psutil.Process().memory_info().rss / 1024 / 1024
        enc_time = time.perf_counter() - start_time

        decrypted = cipher.decrypt_block(ciphertext)
        tag = "N/A"
        verify_tag = tag

    print(f"Key size: {cipher.key_size} bits")
    print(f"Block size: {cipher.block_size} bits")
    if hasattr(cipher, 'rounds'):
        print(f"Rounds: {cipher.rounds}")

    print(f"\nTest Data: 0x{test_data:08X}")
    if cipher.block_size >= 64:
        print(f"Ciphertext: 0x{ciphertext:016X}")
        print(f"Decrypted: 0x{decrypted:016X}")
    else:
        print(f"Ciphertext: 0x{ciphertext:08X}")
        print(f"Decrypted: 0x{decrypted:08X}")

    if tag != "N/A":
        print(f"Auth Tag: 0x{tag:016X}")
        print(f"Tag Valid: {tag == verify_tag}")

    print(f"\nPerformance Metrics:")
    print(f"  Encryption time: {enc_time * 1000:.3f} ms")
    print(f"  CPU usage change: {cpu_after - cpu_before:.1f}%")
    print(f"  Memory usage: {mem_after - mem_before:.3f} MB")

    success = decrypted == test_data if cipher.block_size >= 32 else False
    if cipher.block_size == 32:
        success = (decrypted & 0xFFFFFFFF) == (test_data & 0xFFFFFFFF)

    print(f"\n✓ Success: {success}")
    return success


def main():
    """Test all ciphers"""

    test_data = 0x12345678

    ciphers = [
        (PresentCipher(80), "PRESENT-80"),
        (PresentCipher(128), "PRESENT-128"),
        (SimonCipher('64/128'), "SIMON-64/128"),
        (SpeckCipher('64/128'), "SPECK-64/128"),
        (GiftCipher(), "GIFT-64/128"),
        (TinyJambuCipher(128, '128'), "TinyJambu-128")
    ]

    results = {}

    print("=" * 60)
    print("TESTING ALL LIGHTWEIGHT CRYPTOGRAPHIC ALGORITHMS")
    print("=" * 60)

    for cipher, name in ciphers:
        try:
            success = test_cipher(cipher, name, test_data)
            results[name] = "PASS" if success else "FAIL"
        except Exception as e:
            print(f"\nError testing {name}: {e}")
            import traceback
            traceback.print_exc()
            results[name] = f"ERROR: {str(e)}"

    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    for name, result in results.items():
        if result == "PASS":
            status = "✅"
        elif result == "FAIL":
            status = "❌"
        else:
            status = "⚠️"
        print(f"{status} {name}: {result}")


if __name__ == "__main__":
    main()