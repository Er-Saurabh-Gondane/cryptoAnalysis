"""
Security metrics for cryptographic algorithms
Calculates various security indicators and scores
"""
import os
import sys
import math
from collections import Counter
from typing import Dict, Any, List, Optional

import pandas as pd
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class SecurityMetrics:
    """Calculate security metrics for cryptographic algorithms"""

    def __init__(self):
        # NIST security levels
        self.security_levels = {
            "80": "Low (80-bit)",
            "112": "Medium (112-bit)",
            "128": "High (128-bit)",
            "192": "Very High (192-bit)",
            "256": "Ultra (256-bit)"
        }
        
        # Use conservative, qualitative notes only.
        self.algorithm_notes = {
            "PRESENT": "Widely studied lightweight block cipher; 64-bit block size may limit large-volume use.",
            "SIMON": "Lightweight design intended for constrained devices; often discussed for hardware efficiency.",
            "SPECK": "Lightweight design often noted for software efficiency on constrained platforms.",
            "GIFT": "Modern lightweight block cipher family designed for compact implementations.",
            "TinyJambu": "Lightweight authenticated encryption family with low hardware footprint.",
        }

    def classify_key_strength(self, key_size: int) -> str:
        """Classify key strength."""
        if key_size >= 256:
            return "Ultra"
        if key_size >= 192:
            return "Very High"
        if key_size >= 128:
            return "High"
        if key_size >= 112:
            return "Medium"
        if key_size >= 80:
            return "Low"
        return "Weak"

    def calculate_security_margin_bits(self, key_size: int, attack_complexity_bits: Optional[float]) -> Dict[str, Any]:
        """
        Comparative security margin in bits.

        margin_bits = key_size - attack_complexity_bits

        Positive:
            brute-force harder than best known attack model
        Negative:
            attack model is stronger than naive brute force reference
        """
        if attack_complexity_bits is None:
            return {
                "key_size_bits": key_size,
                "attack_complexity_bits": None,
                "margin_bits": None,
                "note": "Attack complexity not provided",
            }

        margin_bits = key_size - attack_complexity_bits
        return {
            "key_size_bits": key_size,
            "attack_complexity_bits": attack_complexity_bits,
            "margin_bits": margin_bits,
            "note": "Comparative indicator only",
        }

    def estimate_bruteforce_time(
        self,
        key_size: int,
        guesses_per_second: float = 1e9
    ) -> Dict[str, Any]:
        """
        Estimate brute-force effort using average-case search.
        Assumption is purely demonstrative.
        """
        log2_keys = float(key_size)

        # log10(seconds) = log10(2^(key_size - 1) / guesses_per_second)
        log10_seconds = ((key_size - 1) * math.log10(2)) - math.log10(guesses_per_second)
        log10_years = log10_seconds - math.log10(60 * 60 * 24 * 365)

        if log10_years > 12:
            feasibility = "Computationally infeasible"
        elif log10_years > 6:
            feasibility = "Extremely impractical"
        elif log10_years > 1:
            feasibility = "Impractical"
        else:
            feasibility = "Potentially feasible only for weak toy settings"

        return {
            "key_size_bits": key_size,
            "assumed_guesses_per_second": guesses_per_second,
            "log2_keyspace": log2_keys,
            "log10_years_average_case": float(log10_years),
            "feasibility": feasibility,
        }

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy in bits per byte."""
        if not data:
            return 0.0

        counts = Counter(data)
        length = len(data)

        entropy = 0.0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)

        return float(entropy)

    def avalanche_effect_plaintext(
        self,
        cipher: Any,
        plaintext: int,
        key: int,
        block_size: int,
        tested_bits: Optional[int] = None
    ) -> Dict[str, float]:
        """
        Plaintext avalanche test for block ciphers using encrypt_block().
        """
        if tested_bits is None or tested_bits > block_size:
            tested_bits = block_size

        cipher.key_schedule(key)
        original_cipher = cipher.encrypt_block(plaintext)

        bit_changes = []

        for bit in range(tested_bits):
            modified_plaintext = plaintext ^ (1 << bit)
            new_cipher = cipher.encrypt_block(modified_plaintext)

            xor_val = original_cipher ^ new_cipher
            changed_bits = bin(xor_val).count("1")
            percent_changed = (changed_bits / block_size) * 100.0
            bit_changes.append(percent_changed)

        arr = np.array(bit_changes, dtype=float)
        mean_change = float(np.mean(arr))

        return {
            "mean_change_percent": mean_change,
            "std_change_percent": float(np.std(arr)),
            "min_change_percent": float(np.min(arr)),
            "max_change_percent": float(np.max(arr)),
            "distance_from_ideal_50": float(abs(50.0 - mean_change)),
        }

    def get_heuristic_security_index(
        self,
        cipher_name: str,
        key_size: int,
        block_size: int,
        rounds: int
    ) -> Dict[str, Any]:
        """
        Project-specific heuristic indicator, not an absolute security metric.
        """
        score = 0
        max_score = 100
        details = []

        # Key size weight: 45
        if key_size >= 256:
            score += 45
            details.append("Key size is excellent")
        elif key_size >= 128:
            score += 35
            details.append("Key size is strong")
        elif key_size >= 80:
            score += 22
            details.append("Key size is moderate for lightweight context")
        else:
            score += 10
            details.append("Key size is weak")

        # Block size weight: 25
        if block_size >= 128:
            score += 25
            details.append("Block size is large")
        elif block_size >= 64:
            score += 18
            details.append("Block size is acceptable for lightweight block ciphers")
        elif block_size >= 32:
            score += 10
            details.append("Block/state size is limited")
        else:
            score += 5
            details.append("Very small block/state size")

        # Round sufficiency weight: 15
        expected_rounds = {
            "PRESENT": 31,
            "SIMON": 44,
            "SPECK": 27,
            "GIFT": 28,
            "TinyJambu": 384,
        }

        family = cipher_name.split("-")[0]
        expected = expected_rounds.get(family, rounds)

        if rounds >= expected:
            score += 15
            details.append("Configured rounds match reference design")
        else:
            score += 8
            details.append("Configured rounds below typical reference")

        # Design note weight: 15
        if family in self.algorithm_notes:
            score += 15
            details.append("Algorithm is a recognized lightweight design")
        else:
            score += 8
            details.append("Limited design-note information available")

        percentage = (score / max_score) * 100.0

        return {
            "total_score": score,
            "max_score": max_score,
            "percentage": percentage,
            "label": self._get_security_label(percentage),
            "details": details,
            "note": "Heuristic comparative index only",
        }

    def _get_security_label(self, percentage: float) -> str:
        """Heuristic label."""
        if percentage >= 85:
            return "Very Strong (heuristic)"
        if percentage >= 70:
            return "Strong (heuristic)"
        if percentage >= 55:
            return "Moderate (heuristic)"
        if percentage >= 40:
            return "Limited (heuristic)"
        return "Weak (heuristic)"

    def compare_algorithms(self, ciphers_info: List[Dict[str, Any]]) -> pd.DataFrame:
        """Compare algorithms using comparative indicators."""
        rows = []

        for info in ciphers_info:
            name = info["name"]
            key_size = int(info["key_size"])
            block_size = int(info["block_size"])
            rounds = int(info["rounds"])

            heuristic = self.get_heuristic_security_index(name, key_size, block_size, rounds)
            bf = self.estimate_bruteforce_time(key_size)

            rows.append({
                "Cipher": name,
                "Key Size (bits)": key_size,
                "Block Size (bits)": block_size,
                "Rounds": rounds,
                "Key Strength": self.classify_key_strength(key_size),
                "Heuristic Security Index (%)": round(heuristic["percentage"], 2),
                "Heuristic Label": heuristic["label"],
                "Bruteforce log10(years)": round(bf["log10_years_average_case"], 2),
                "Bruteforce Feasibility": bf["feasibility"],
                "Design Note": self.algorithm_notes.get(name.split("-")[0], "No note available"),
            })

        return pd.DataFrame(rows)


if __name__ == "__main__":
    metrics = SecurityMetrics()

    ciphers_info = [
        {"name": "PRESENT-80", "key_size": 80, "block_size": 64, "rounds": 31},
        {"name": "PRESENT-128", "key_size": 128, "block_size": 64, "rounds": 31},
        {"name": "SIMON-64/128", "key_size": 128, "block_size": 64, "rounds": 44},
        {"name": "SPECK-64/128", "key_size": 128, "block_size": 64, "rounds": 27},
        {"name": "GIFT-64/128", "key_size": 128, "block_size": 64, "rounds": 28},
        {"name": "TinyJambu-128", "key_size": 128, "block_size": 32, "rounds": 384},
    ]

    print("=" * 80)
    print("SECURITY INDICATORS COMPARISON")
    print("=" * 80)
    comparison_df = metrics.compare_algorithms(ciphers_info)
    print(comparison_df.to_string(index=False))