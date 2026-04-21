"""
Brute force attack demonstration for the IoT cryptography project.

Important:
- This module does NOT brute-force real project ciphers.
- It demonstrates brute force on a toy keyspace only.
- For actual algorithm key sizes, it reports theoretical brute-force infeasibility.
- Includes comparisons with known historical attacks for context.
"""

import os
import sys
import json
import time
import math
from datetime import datetime
from typing import Dict, Any, List, Tuple
import matplotlib.pyplot as plt
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from evaluation.metrics import SecurityMetrics


class BruteForceDemo:
    """Demonstrate brute force on a toy cipher and estimate real key strength."""

    def __init__(self, output_dir: str = "../results/attacks"):
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.metrics = SecurityMetrics()

    @staticmethod
    def toy_encrypt(plaintext: bytes, key: int) -> bytes:
        """
        Toy XOR encryption for brute-force demonstration.
        This is intentionally simple and NOT a real secure cipher.
        """
        key_byte = key & 0xFF
        return bytes([b ^ key_byte for b in plaintext])

    def run_toy_demo(self, secret_key: int = 57, key_bits: int = 8) -> Dict[str, Any]:
        """
        Brute-force a toy cipher with configurable key size.
        
        Args:
            secret_key: The secret key to find
            key_bits: Size of keyspace (1-24 bits for demo)
        """
        if key_bits > 24:
            key_bits = 24  # Limit for demo runtime
            
        plaintext = b"IOT"
        ciphertext = self.toy_encrypt(plaintext, secret_key)

        start = time.perf_counter()
        recovered_key = None
        attempts = 0
        keyspace = 2 ** key_bits

        for candidate_key in range(keyspace):
            attempts += 1
            decrypted = self.toy_encrypt(ciphertext, candidate_key)
            if decrypted == plaintext:
                recovered_key = candidate_key
                break

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        elapsed_seconds = elapsed_ms / 1000.0

        # Calculate rate
        if elapsed_seconds > 0:
            attempts_per_second = attempts / elapsed_seconds
        else:
            attempts_per_second = 0

        return {
            "toy_plaintext": plaintext.decode("utf-8"),
            "toy_ciphertext_hex": ciphertext.hex(),
            "secret_key": secret_key,
            "recovered_key": recovered_key,
            "key_bits": key_bits,
            "keyspace_size": keyspace,
            "key_recovered": recovered_key == secret_key,
            "attempts": attempts,
            "elapsed_ms": elapsed_ms,
            "attempts_per_second": attempts_per_second,
            "keyspace_explored_percent": (attempts / keyspace) * 100,
            "note": f"Toy {key_bits}-bit XOR demo only, not representative of real lightweight ciphers",
        }

    def run_multiple_toy_demos(self, max_bits: int = 16) -> List[Dict[str, Any]]:
        """
        Run toy demos with increasing key sizes to show exponential growth.
        """
        print("\n📊 Running toy demos with increasing key sizes...")
        results = []
        
        # Use a fixed secret key pattern
        for bits in range(8, max_bits + 1, 2):
            print(f"  Testing {bits}-bit keyspace...")
            secret = 0xAA & ((1 << bits) - 1)  # Pattern that fits in bits
            result = self.run_toy_demo(secret_key=secret, key_bits=bits)
            results.append(result)
            
        return results

    def analyze_real_algorithms(self) -> List[Dict[str, Any]]:
        """Estimate brute-force infeasibility for real project algorithms."""
        algorithms = [
            {"name": "PRESENT-80", "key_size": 80, "type": "Lightweight Block Cipher"},
            {"name": "PRESENT-128", "key_size": 128, "type": "Lightweight Block Cipher"},
            {"name": "SIMON-64/128", "key_size": 128, "type": "Lightweight Block Cipher"},
            {"name": "SPECK-64/128", "key_size": 128, "type": "Lightweight Block Cipher"},
            {"name": "GIFT-64/128", "key_size": 128, "type": "Lightweight Block Cipher"},
            {"name": "TinyJambu-128", "key_size": 128, "type": "Authenticated Cipher"},
            {"name": "AES-128", "key_size": 128, "type": "Standard (Reference)"},
            {"name": "AES-256", "key_size": 256, "type": "Standard (Reference)"},
        ]

        results = []
        for algo in algorithms:
            bf = self.metrics.estimate_bruteforce_time(algo["key_size"])
            
            # Calculate actual numbers for context
            years = 10 ** bf["log10_years_average_case"]
            
            # Human-readable time
            if years > 1e9:
                time_str = f"{years/1e9:.2f} billion years"
            elif years > 1e6:
                time_str = f"{years/1e6:.2f} million years"
            elif years > 1e3:
                time_str = f"{years/1e3:.2f} thousand years"
            else:
                time_str = f"{years:.2f} years"
            
            results.append({
                "algorithm": algo["name"],
                "type": algo["type"],
                "key_size_bits": algo["key_size"],
                "log10_years": bf["log10_years_average_case"],
                "years_estimate": time_str,
                "feasibility": bf["feasibility"],
                "comparison": self._get_comparison_context(algo["key_size"]),
            })

        return results
    
    def _get_comparison_context(self, key_size: int) -> str:
        """Provide context for key strength comparison."""
        if key_size >= 256:
            return "Stronger than all known practical attacks"
        elif key_size >= 128:
            return "NIST recommended minimum for 2030+"
        elif key_size >= 80:
            return "Legacy security level (phasing out)"
        else:
            return "Insecure for modern systems"

    def plot_key_size_comparison(self, toy_results: List[Dict[str, Any]], 
                                 real_results: List[Dict[str, Any]], 
                                 save: bool = True) -> None:
        """
        Create visualization comparing toy vs real key sizes.
        """
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
        
        # Plot 1: Toy demo scaling
        bits = [r["key_bits"] for r in toy_results]
        times = [r["elapsed_ms"] for r in toy_results]
        
        ax1.plot(bits, times, 'bo-', linewidth=2, markersize=8)
        ax1.set_xlabel("Key Size (bits)")
        ax1.set_ylabel("Brute Force Time (ms)")
        ax1.set_title("Toy XOR Cipher - Brute Force Time")
        ax1.set_yscale('log')
        ax1.grid(True, alpha=0.3)
        
        # Add exponential trend
        if len(bits) > 2:
            z = np.polyfit(bits, np.log(times), 1)
            trend = np.exp(np.polyval(z, bits))
            ax1.plot(bits, trend, 'r--', alpha=0.5, label=f'Exponential trend (2^{z[0]:.2f}x per bit)')
            ax1.legend()
        
        # Plot 2: Real algorithm comparison
        names = [r["algorithm"] for r in real_results[:6]]  # First 6 algorithms
        log_years = [r["log10_years"] for r in real_results[:6]]
        
        colors = ['green' if y > 20 else 'orange' if y > 10 else 'red' for y in log_years]
        bars = ax2.barh(names, log_years, color=colors)
        
        ax2.set_xlabel("log10(Years) for Brute Force")
        ax2.set_title("Real Algorithm - Theoretical Brute Force Time")
        
        # Add value labels
        for bar, val in zip(bars, log_years):
            ax2.text(val + 0.1, bar.get_y() + bar.get_height()/2, 
                    f'10^{val:.1f} years', va='center')
        
        # Add reference line for universe age (13.8B years ≈ 10^10)
        ax2.axvline(x=10, color='red', linestyle='--', alpha=0.5, 
                   label='Universe age (~10^10 years)')
        ax2.legend()
        
        plt.tight_layout()
        
        if save:
            graph_path = os.path.join(self.output_dir, "bruteforce_comparison.png")
            plt.savefig(graph_path, dpi=300, bbox_inches='tight')
            print(f"\n📊 Graph saved to: {graph_path}")
        
        plt.close()

    def run_comprehensive(self) -> Dict[str, Any]:
        """Run comprehensive brute force analysis."""
        print("=" * 80)
        print("🔓 BRUTE FORCE COMPREHENSIVE ANALYSIS")
        print("=" * 80)
        
        # Run toy demos
        print("\n🔬 Running toy XOR demos...")
        toy_demos = self.run_multiple_toy_demos(max_bits=16)
        
        # Analyze real algorithms
        print("\n🔐 Analyzing real algorithms...")
        real_analysis = self.analyze_real_algorithms()
        
        # Run a single 8-bit demo for basic result
        basic_toy = self.run_toy_demo(secret_key=57, key_bits=8)
        
        # Generate comparison plot
        self.plot_key_size_comparison(toy_demos, real_analysis)
        
        result = {
            "attack_name": "Brute Force Comprehensive Analysis",
            "timestamp": datetime.now().isoformat(),
            "toy_demos": toy_demos,
            "basic_toy_demo": basic_toy,
            "real_algorithm_analysis": real_analysis,
            "summary": {
                "toy_demos_completed": len(toy_demos),
                "max_toy_bits_tested": max(r["key_bits"] for r in toy_demos),
                "real_keys_bruteforce_practical": False,
                "fastest_real_algorithm": min(real_analysis, key=lambda x: x["log10_years"])["algorithm"],
                "slowest_real_algorithm": max(real_analysis, key=lambda x: x["log10_years"])["algorithm"],
            },
            "conclusion": "Real cryptographic algorithms are completely immune to brute force attacks. "
                         "Even the weakest algorithm (80-bit) would take millions of years to break."
        }

        self._save_result(result, "comprehensive")
        return result

    def run(self) -> Dict[str, Any]:
        """Run basic brute force demo."""
        toy = self.run_toy_demo(secret_key=57, key_bits=8)
        real = self.analyze_real_algorithms()

        result = {
            "attack_name": "Brute Force Demo",
            "timestamp": datetime.now().isoformat(),
            "toy_demo": toy,
            "real_algorithm_analysis": real,
            "summary": {
                "toy_demo_successful": toy["key_recovered"],
                "real_keys_bruteforce_practical": False,
                "note": "Real algorithms are computationally infeasible to brute force"
            }
        }

        self._save_result(result, "basic")
        return result

    def _save_result(self, result: Dict[str, Any], mode: str = "basic") -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"bruteforce_{mode}_{timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    @staticmethod
    def print_result(result: Dict[str, Any]) -> None:
        """Print basic demo result."""
        print("=" * 80)
        print("🔓 BRUTE FORCE DEMO")
        print("=" * 80)

        if "basic_toy_demo" in result:
            # Comprehensive mode
            toy = result["basic_toy_demo"]
        else:
            # Basic mode
            toy = result["toy_demo"]
            
        print("\n🎮 Toy XOR Cipher Demo:")
        print(f"  Plaintext: {toy['toy_plaintext']}")
        print(f"  Ciphertext (hex): {toy['toy_ciphertext_hex']}")
        print(f"  Secret Key: {toy['secret_key']}")
        print(f"  Recovered Key: {toy['recovered_key']}")
        print(f"  Key Bits: {toy['key_bits']}")
        print(f"  Attempts: {toy['attempts']:,}")
        print(f"  Time: {toy['elapsed_ms']:.4f} ms")
        print(f"  Success: {'✅' if toy['key_recovered'] else '❌'}")
        print(f"  Note: {toy['note']}")

        print("\n🔐 Real Algorithm Key Strength:")
        for row in result["real_algorithm_analysis"]:
            status = "✅" if "infeasible" in row['feasibility'].lower() else "⚠️"
            print(
                f"  {status} {row['algorithm']}: {row['key_size_bits']} bits | "
                f"{row['years_estimate']} | {row['feasibility']}"
            )
        
        if "conclusion" in result:
            print(f"\n📌 Conclusion: {result['conclusion']}")

    @staticmethod
    def print_summary(result: Dict[str, Any]) -> None:
        """Print comprehensive summary."""
        print("\n" + "=" * 80)
        print("📊 BRUTE FORCE SUMMARY")
        print("=" * 80)
        
        print("\n🎮 Toy XOR Demos Scaling:")
        for demo in result["toy_demos"]:
            print(f"  {demo['key_bits']:2d} bits: {demo['attempts']:6d} attempts, "
                  f"{demo['elapsed_ms']:8.2f} ms, "
                  f"{demo['attempts_per_second']:10.0f} attempts/sec")
        
        print("\n🔐 Real Algorithm Comparison:")
        for row in result["real_algorithm_analysis"]:
            print(f"  {row['algorithm']:15s} | {row['key_size_bits']:3d} bits | "
                  f"10^{row['log10_years']:5.1f} years | {row['comparison']}")
        
        print(f"\n📌 {result['conclusion']}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Brute Force Demo')
    parser.add_argument('--mode', choices=['basic', 'comprehensive'], default='basic',
                       help='Run basic or comprehensive analysis')
    args = parser.parse_args()
    
    demo = BruteForceDemo()
    
    if args.mode == 'comprehensive':
        print("🔬 Running comprehensive brute force analysis...")
        result = demo.run_comprehensive()
        demo.print_summary(result)
    else:
        print("🎯 Running basic brute force demo...")
        result = demo.run()
        demo.print_result(result)
    
    print(f"\n📁 Results saved in: {demo.output_dir}")