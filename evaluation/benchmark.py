"""
Benchmark module for measuring cryptographic algorithm performance
Measures encryption/decryption speed, latency, response time,
message size, bit size, memory usage, and CPU utilization.
"""

import os
import sys
import gc
import time
import json
import hashlib
import tracemalloc
import platform
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable

import pandas as pd
import numpy as np
import psutil

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.present_cipher import PresentCipher
from crypto.simon_cipher import SimonCipher
from crypto.speck_cipher import SpeckCipher
from crypto.gift_cipher import GiftCipher
from crypto.tinyjambu_cipher import TinyJambuCipher


class CryptoBenchmark:
    """Benchmark cryptographic algorithms for IoT devices"""

    DEFAULT_DATA_SIZES = [16, 64, 256, 1024]
    DEFAULT_NETWORK_DELAY_MS = 1.0

    def __init__(self, output_dir: str = "../results"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.demo_key = 0x0123456789ABCDEF0123456789ABCDEF
        self.results = pd.DataFrame()

        self.cipher_configs = {
            "PRESENT-80": {"type": "present", "key_size": 80},
            "PRESENT-128": {"type": "present", "key_size": 128},
            "SIMON-64/128": {"type": "simon", "variant": "64/128"},
            "SPECK-64/128": {"type": "speck", "variant": "64/128"},
            "GIFT-64/128": {"type": "gift"},
            "TinyJambu-128": {"type": "tinyjambu", "key_size": 128, "variant": "128"},
        }

    def _get_demo_key_for_cipher(self, cipher_name: str) -> int:
        if cipher_name == "PRESENT-80":
            return self.demo_key & ((1 << 80) - 1)
        return self.demo_key & ((1 << 128) - 1)

    def _int_to_key_bytes(self, key: int, size_bits: int = 128) -> bytes:
        return key.to_bytes(size_bits // 8, byteorder="big", signed=False)

    def _int_to_words32(self, key: int, size_bits: int = 128) -> List[int]:
        key_bytes = self._int_to_key_bytes(key, size_bits)
        return [
            int.from_bytes(key_bytes[i:i + 4], byteorder="big", signed=False)
            for i in range(0, len(key_bytes), 4)
        ]

    def _init_present(self, key_size: int, key: int):
        cipher = PresentCipher(key_size)
        cipher.key_schedule(key)
        return cipher

    def _init_simon(self, variant: str, key: int):
        cipher = SimonCipher(variant)
        cipher.key_schedule(key)
        return cipher

    def _init_speck(self, variant: str, key: int):
        cipher = SpeckCipher(variant)
        cipher.key_schedule(key)
        return cipher

    def _init_gift(self, key: int):
        cipher = GiftCipher()
        cipher.key_schedule(key)
        return cipher

    # ==================== FIXED TINYJAMBU INITIALIZATION ====================
    def _init_tinyjambu(self, key: int):
        """Initialize TinyJambu with proper key scheduling"""
        cipher = TinyJambuCipher(128, "128")
        cipher.key_schedule(key)
        return cipher
    # ==================== END OF TINYJAMBU FIX ====================

    def _create_cipher(self, cipher_name: str) -> Any:
        cfg = self.cipher_configs[cipher_name]
        key = self._get_demo_key_for_cipher(cipher_name)

        if cfg["type"] == "present":
            return self._init_present(cfg["key_size"], key)
        elif cfg["type"] == "simon":
            return self._init_simon(cfg["variant"], key)
        elif cfg["type"] == "speck":
            return self._init_speck(cfg["variant"], key)
        elif cfg["type"] == "gift":
            return self._init_gift(key)
        elif cfg["type"] == "tinyjambu":
            return self._init_tinyjambu(key)
        else:
            raise ValueError(f"Unsupported cipher type: {cipher_name}")

    def _get_cipher_metadata(self, cipher_name: str, cipher: Any) -> Dict[str, Any]:
        return {
            "cipher": cipher_name,
            "block_size": getattr(cipher, "block_size", None),
            "key_size": getattr(cipher, "key_size", None),
        }

    # ==================== FIXED TINYJAMBU ENCRYPT/DECRYPT ====================
    def _generate_tinyjambu_nonce(self, seed: int) -> int:
        """Generate a proper 96-bit nonce for TinyJambu"""
        # TinyJambu requires exactly 96 bits (12 bytes)
        seed_bytes = seed.to_bytes(16, byteorder='big')
        hash_bytes = hashlib.sha256(seed_bytes).digest()
        nonce_bytes = hash_bytes[:12]  # Take first 96 bits
        return int.from_bytes(nonce_bytes, byteorder='big')

    def _encrypt_message(self, cipher_name: str, data: bytes, nonce_seed: int = 0) -> bytes:
        cipher = self._create_cipher(cipher_name)

        if "TinyJambu" in cipher_name:
            # Generate proper 96-bit nonce
            nonce = self._generate_tinyjambu_nonce(nonce_seed)
            return cipher.encrypt(data, nonce=nonce)

        return cipher.encrypt(data)

    def _decrypt_message(self, cipher_name: str, encrypted: bytes, nonce_seed: int = 0) -> bytes:
        cipher = self._create_cipher(cipher_name)

        if "TinyJambu" in cipher_name:
            # Generate proper 96-bit nonce
            nonce = self._generate_tinyjambu_nonce(nonce_seed)
            return cipher.decrypt(encrypted, nonce=nonce)

        return cipher.decrypt(encrypted)
    # ==================== END OF TINYJAMBU FIX ====================

    def _verify_correctness(self, cipher_name: str, data: bytes) -> bool:
        try:
            encrypted = self._encrypt_message(cipher_name, data, nonce_seed=1)
            decrypted = self._decrypt_message(cipher_name, encrypted, nonce_seed=1)
            return decrypted == data
        except Exception as e:
            print(f"    Correctness check failed for {cipher_name}: {e}")
            return False

    def measure_execution_time(
        self,
        func: Callable,
        *args,
        iterations: int = 200,
        warmup: int = 20
    ) -> Dict[str, float]:
        for _ in range(warmup):
            func(*args)

        times_ms = []
        for _ in range(iterations):
            start = time.perf_counter()
            func(*args)
            end = time.perf_counter()
            times_ms.append((end - start) * 1000.0)

        arr = np.array(times_ms, dtype=float)
        return {
            "mean": float(np.mean(arr)),
            "median": float(np.median(arr)),
            "std": float(np.std(arr)),
            "min": float(np.min(arr)),
            "max": float(np.max(arr)),
            "p95": float(np.percentile(arr, 95)),
            "p99": float(np.percentile(arr, 99)),
        }

    def measure_throughput(
        self,
        cipher_name: str,
        data_size: int,
        iterations: int = 100
    ) -> Dict[str, float]:
        data = os.urandom(data_size)

        start = time.perf_counter()
        total_bytes = 0
        for i in range(iterations):
            encrypted = self._encrypt_message(cipher_name, data, nonce_seed=i)
            total_bytes += len(encrypted)
        end = time.perf_counter()

        elapsed = end - start
        throughput_mbps = (total_bytes / elapsed) / (1024 * 1024) if elapsed > 0 else 0.0

        return {
            "throughput_mbps": float(throughput_mbps),
            "total_bytes": int(total_bytes),
            "elapsed_seconds": float(elapsed),
            "iterations": int(iterations),
        }

    def measure_memory_usage(
        self,
        cipher_name: str,
        data_size: int,
        iterations: int = 20
    ) -> Dict[str, float]:
        data = os.urandom(data_size)
        gc.collect()

        tracemalloc.start()
        for i in range(iterations):
            self._encrypt_message(cipher_name, data, nonce_seed=i)
        current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        return {
            "current_memory_kb": float(current / 1024.0),
            "peak_memory_kb": float(peak / 1024.0),
        }

    def measure_process_cpu(
        self,
        cipher_name: str,
        data_size: int,
        duration: float = 2.0
    ) -> Dict[str, float]:
        process = psutil.Process(os.getpid())
        data = os.urandom(data_size)

        start_wall = time.perf_counter()
        cpu_start = process.cpu_times()
        iterations = 0

        while (time.perf_counter() - start_wall) < duration:
            self._encrypt_message(cipher_name, data, nonce_seed=iterations)
            iterations += 1

        cpu_end = process.cpu_times()
        wall_elapsed = time.perf_counter() - start_wall

        user_cpu = cpu_end.user - cpu_start.user
        system_cpu = cpu_end.system - cpu_start.system
        total_cpu = user_cpu + system_cpu

        cpu_util_percent = (total_cpu / wall_elapsed) * 100.0 if wall_elapsed > 0 else 0.0
        iterations_per_second = iterations / wall_elapsed if wall_elapsed > 0 else 0.0

        return {
            "process_cpu_time_sec": float(total_cpu),
            "process_cpu_util_percent": float(cpu_util_percent),
            "iterations_per_second": float(iterations_per_second),
        }

    def _build_environment_metadata(self) -> Dict[str, Any]:
        return {
            "timestamp": datetime.now().isoformat(),
            "python_version": sys.version.replace("\n", " "),
            "platform": platform.platform(),
            "processor": platform.processor(),
            "cpu_count_logical": psutil.cpu_count(logical=True),
            "cpu_count_physical": psutil.cpu_count(logical=False),
            "memory_total_gb": round(psutil.virtual_memory().total / (1024 ** 3), 2),
        }

    def run_comprehensive_benchmark(
        self,
        data_sizes: Optional[List[int]] = None,
        iterations: int = 200,
        throughput_iterations: int = 100,
        cpu_duration: float = 2.0,
        network_delay_ms: float = DEFAULT_NETWORK_DELAY_MS
    ) -> pd.DataFrame:
        if data_sizes is None:
            data_sizes = self.DEFAULT_DATA_SIZES

        print("=" * 80)
        print("Running Comprehensive Crypto Benchmark")
        print("=" * 80)

        results = []
        metadata = self._build_environment_metadata()

        for cipher_name in self.cipher_configs.keys():
            print(f"\nBenchmarking {cipher_name}...")

            try:
                meta_cipher = self._create_cipher(cipher_name)
            except Exception as e:
                print(f"  Skipping {cipher_name}: initialization failed -> {e}")
                continue

            for size in data_sizes:
                print(f"  Data size: {size} bytes")
                plaintext = os.urandom(size)

                correctness_ok = self._verify_correctness(cipher_name, plaintext)

                if not correctness_ok:
                    print(f"    Skipping size {size} for {cipher_name}: correctness failed")
                    continue

                enc_timing = self.measure_execution_time(
                    self._encrypt_message,
                    cipher_name, plaintext, 7,
                    iterations=iterations,
                    warmup=max(10, iterations // 10),
                )

                encrypted_sample = self._encrypt_message(cipher_name, plaintext, 7)

                dec_timing = self.measure_execution_time(
                    self._decrypt_message,
                    cipher_name, encrypted_sample, 7,
                    iterations=iterations,
                    warmup=max(10, iterations // 10),
                )

                throughput = self.measure_throughput(
                    cipher_name, size, iterations=throughput_iterations
                )

                memory = self.measure_memory_usage(cipher_name, size, iterations=20)

                cpu = self.measure_process_cpu(
                    cipher_name, size, duration=cpu_duration
                )

                latency_time_ms = enc_timing["mean"] + dec_timing["mean"]
                response_time_ms = enc_timing["mean"] + network_delay_ms + dec_timing["mean"]

                results.append({
                    **self._get_cipher_metadata(cipher_name, meta_cipher),
                    "message_size_bytes": size,
                    "message_size_bits": size * 8,
                    "data_size_bytes": size,
                    "correctness_passed": correctness_ok,
                    "encryption_time_ms": enc_timing["mean"],
                    "encryption_time_std_ms": enc_timing["std"],
                    "encryption_time_p95_ms": enc_timing["p95"],
                    "decryption_time_ms": dec_timing["mean"],
                    "decryption_time_std_ms": dec_timing["std"],
                    "decryption_time_p95_ms": dec_timing["p95"],
                    "latency_time_ms": latency_time_ms,
                    "response_time_ms": response_time_ms,
                    "network_delay_ms": network_delay_ms,
                    "throughput_mbps": throughput["throughput_mbps"],
                    "memory_current_kb": memory["current_memory_kb"],
                    "memory_peak_kb": memory["peak_memory_kb"],
                    "process_cpu_time_sec": cpu["process_cpu_time_sec"],
                    "process_cpu_util_percent": cpu["process_cpu_util_percent"],
                    "iterations_per_second": cpu["iterations_per_second"],
                    "benchmark_iterations": iterations,
                    "throughput_iterations": throughput_iterations,
                    "cpu_measure_duration_sec": cpu_duration,
                    "benchmark_timestamp": metadata["timestamp"],
                    "python_version": metadata["python_version"],
                    "platform": metadata["platform"],
                    "processor": metadata["processor"],
                    "cpu_count_logical": metadata["cpu_count_logical"],
                    "cpu_count_physical": metadata["cpu_count_physical"],
                    "memory_total_gb": metadata["memory_total_gb"],
                })

        df = pd.DataFrame(results)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_path = os.path.join(self.output_dir, f"benchmark_results_{timestamp}.csv")
        meta_path = os.path.join(self.output_dir, f"benchmark_metadata_{timestamp}.json")

        df.to_csv(csv_path, index=False)
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        print(f"\nResults saved to: {csv_path}")
        print(f"Metadata saved to: {meta_path}")

        self.results = df
        return df

    def print_summary(self, df: Optional[pd.DataFrame] = None) -> None:
        if df is None:
            df = self.results

        if df is None or df.empty:
            print("No benchmark results available")
            return

        print("\n" + "=" * 80)
        print("BENCHMARK SUMMARY")
        print("=" * 80)

        for cipher in df["cipher"].unique():
            cipher_data = df[df["cipher"] == cipher]

            print(f"\n{cipher}:")
            print(f"  Block Size: {cipher_data['block_size'].iloc[0]} bits")
            print(f"  Key Size: {cipher_data['key_size'].iloc[0]} bits")
            print(f"  Correctness Passed: {cipher_data['correctness_passed'].all()}")
            print(f"  Avg Encryption Time: {cipher_data['encryption_time_ms'].mean():.4f} ms")
            print(f"  Avg Decryption Time: {cipher_data['decryption_time_ms'].mean():.4f} ms")
            print(f"  Avg Latency Time: {cipher_data['latency_time_ms'].mean():.4f} ms")
            print(f"  Avg Response Time: {cipher_data['response_time_ms'].mean():.4f} ms")
            print(f"  Avg Throughput: {cipher_data['throughput_mbps'].mean():.4f} MB/s")
            print(f"  Avg Peak Memory: {cipher_data['memory_peak_kb'].mean():.2f} KB")
            print(f"  Avg Process CPU Util: {cipher_data['process_cpu_util_percent'].mean():.2f}%")


if __name__ == "__main__":
    benchmark = CryptoBenchmark()
    results = benchmark.run_comprehensive_benchmark()
    benchmark.print_summary()