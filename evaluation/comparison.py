"""
Comparison module for cryptographic algorithms
Generates comparison tables and visualizations
"""

import os
import sys
from datetime import datetime
from typing import Optional

import pandas as pd
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from evaluation.benchmark import CryptoBenchmark
from evaluation.metrics import SecurityMetrics


class CryptoComparison:
    """Compare multiple cryptographic algorithms."""

    def __init__(self, output_dir: Optional[str] = None):
        if output_dir is None:
            output_dir = os.path.join(BASE_DIR, "results", "graphs")
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def load_benchmark_data(self, csv_path: Optional[str] = None) -> pd.DataFrame:
        if csv_path and os.path.exists(csv_path):
            print(f"Loading benchmark data from: {csv_path}")
            df = pd.read_csv(csv_path)
        else:
            print("Running new benchmark...")
            benchmark = CryptoBenchmark()
            df = benchmark.run_comprehensive_benchmark()

        print("\nAvailable columns in dataframe:")
        print(df.columns.tolist())
        return df

    def plot_encryption_time(self, df: pd.DataFrame, save: bool = True) -> None:
        pivot = df.pivot_table(
            values="encryption_time_ms",
            index="message_size_bytes",
            columns="cipher",
            aggfunc="mean",
        )

        fig, ax = plt.subplots(figsize=(12, 6))
        for cipher in pivot.columns:
            ax.plot(pivot.index, pivot[cipher], marker="o", linewidth=2, label=cipher)

        ax.set_xlabel("Message Size (bytes)")
        ax.set_ylabel("Encryption Time (ms)")
        ax.set_title("Encryption Time vs Message Size")
        ax.set_xscale("log")
        ax.grid(True, alpha=0.3)
        ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")

        fig.tight_layout()
        if save:
            save_path = os.path.join(self.output_dir, "encryption_time.png")
            fig.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")
        plt.close(fig)

    def plot_decryption_time(self, df: pd.DataFrame, save: bool = True) -> None:
        pivot = df.pivot_table(
            values="decryption_time_ms",
            index="message_size_bytes",
            columns="cipher",
            aggfunc="mean",
        )

        fig, ax = plt.subplots(figsize=(12, 6))
        for cipher in pivot.columns:
            ax.plot(pivot.index, pivot[cipher], marker="s", linewidth=2, label=cipher)

        ax.set_xlabel("Message Size (bytes)")
        ax.set_ylabel("Decryption Time (ms)")
        ax.set_title("Decryption Time vs Message Size")
        ax.set_xscale("log")
        ax.grid(True, alpha=0.3)
        ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")

        fig.tight_layout()
        if save:
            save_path = os.path.join(self.output_dir, "decryption_time.png")
            fig.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")
        plt.close(fig)

    def plot_latency_time(self, df: pd.DataFrame, save: bool = True) -> None:
        pivot = df.pivot_table(
            values="latency_time_ms",
            index="message_size_bytes",
            columns="cipher",
            aggfunc="mean",
        )

        fig, ax = plt.subplots(figsize=(12, 6))
        for cipher in pivot.columns:
            ax.plot(pivot.index, pivot[cipher], marker="^", linewidth=2, label=cipher)

        ax.set_xlabel("Message Size (bytes)")
        ax.set_ylabel("Latency Time (ms)")
        ax.set_title("Latency Time vs Message Size")
        ax.set_xscale("log")
        ax.grid(True, alpha=0.3)
        ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")

        fig.tight_layout()
        if save:
            save_path = os.path.join(self.output_dir, "latency_time.png")
            fig.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")
        plt.close(fig)

    def plot_response_time(self, df: pd.DataFrame, save: bool = True) -> None:
        pivot = df.pivot_table(
            values="response_time_ms",
            index="message_size_bytes",
            columns="cipher",
            aggfunc="mean",
        )

        fig, ax = plt.subplots(figsize=(12, 6))
        for cipher in pivot.columns:
            ax.plot(pivot.index, pivot[cipher], marker="d", linewidth=2, label=cipher)

        ax.set_xlabel("Message Size (bytes)")
        ax.set_ylabel("Response Time (ms)")
        ax.set_title("Response Time vs Message Size")
        ax.set_xscale("log")
        ax.grid(True, alpha=0.3)
        ax.legend(bbox_to_anchor=(1.05, 1), loc="upper left")

        fig.tight_layout()
        if save:
            save_path = os.path.join(self.output_dir, "response_time.png")
            fig.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")
        plt.close(fig)

    def plot_throughput(self, df: pd.DataFrame, save: bool = True) -> None:
        avg_throughput = df.groupby("cipher")["throughput_mbps"].mean().sort_values(ascending=False)

        fig, ax = plt.subplots(figsize=(12, 6))
        bars = ax.bar(avg_throughput.index, avg_throughput.values)

        ax.set_xlabel("Algorithm")
        ax.set_ylabel("Throughput (MB/s)")
        ax.set_title("Average Throughput by Algorithm")
        ax.tick_params(axis="x", rotation=45)

        for bar, val in zip(bars, avg_throughput.values):
            ax.text(bar.get_x() + bar.get_width() / 2, val, f"{val:.2f}",
                    ha="center", va="bottom")

        fig.tight_layout()
        if save:
            save_path = os.path.join(self.output_dir, "throughput.png")
            fig.savefig(save_path, dpi=300, bbox_inches="tight")
            print(f"Saved: {save_path}")
        plt.close(fig)

    def generate_all_graphs(self, df: pd.DataFrame) -> None:
        self.plot_encryption_time(df)
        self.plot_decryption_time(df)
        self.plot_latency_time(df)
        self.plot_response_time(df)
        self.plot_throughput(df)
        print(f"\nAll graphs saved in: {self.output_dir}")

    def generate_comparison_table(self, df: pd.DataFrame) -> pd.DataFrame:
        comparison = df.groupby("cipher").agg({
            "block_size": "first",
            "key_size": "first",
            "message_size_bytes": "mean",
            "message_size_bits": "mean",
            "correctness_passed": "all",
            "encryption_time_ms": "mean",
            "decryption_time_ms": "mean",
            "latency_time_ms": "mean",
            "response_time_ms": "mean",
            "throughput_mbps": "mean",
            "memory_peak_kb": "mean",
            "process_cpu_util_percent": "mean",
        }).round(4)

        metrics = SecurityMetrics()
        heuristic_values = []
        heuristic_labels = []

        for cipher in comparison.index:
            block = int(comparison.loc[cipher, "block_size"])
            key = int(comparison.loc[cipher, "key_size"])

            if "PRESENT" in cipher:
                rounds = 31
            elif "SIMON" in cipher:
                rounds = 44
            elif "SPECK" in cipher:
                rounds = 27
            elif "GIFT" in cipher:
                rounds = 28
            elif "TinyJambu" in cipher:
                rounds = 384
            else:
                rounds = 0

            heuristic = metrics.get_heuristic_security_index(cipher, key, block, rounds)
            heuristic_values.append(round(heuristic["percentage"], 2))
            heuristic_labels.append(heuristic["label"])

        comparison["heuristic_security_index"] = heuristic_values
        comparison["heuristic_label"] = heuristic_labels

        comparison.columns = [
            "Block (bits)",
            "Key (bits)",
            "Avg Msg Size (bytes)",
            "Avg Msg Size (bits)",
            "Correctness",
            "Enc Time (ms)",
            "Dec Time (ms)",
            "Latency Time (ms)",
            "Response Time (ms)",
            "Throughput (MB/s)",
            "Peak Memory (KB)",
            "CPU Util (%)",
            "Heuristic Security Index (%)",
            "Heuristic Label",
        ]

        return comparison

    def create_summary_report(self, df: pd.DataFrame, save: bool = True) -> pd.DataFrame:
        print("\n" + "=" * 80)
        print("CRYPTOGRAPHIC ALGORITHMS COMPARISON REPORT")
        print("=" * 80)

        comparison = self.generate_comparison_table(df)
        print("\nPerformance and Comparison Table:")
        print(comparison.to_string())

        print("\nCategory Leaders:")
        print(f"  Fastest Encryption: {comparison['Enc Time (ms)'].idxmin()}")
        print(f"  Fastest Decryption: {comparison['Dec Time (ms)'].idxmin()}")
        print(f"  Lowest Latency: {comparison['Latency Time (ms)'].idxmin()}")
        print(f"  Lowest Response Time: {comparison['Response Time (ms)'].idxmin()}")
        print(f"  Highest Throughput: {comparison['Throughput (MB/s)'].idxmax()}")

        if save:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_path = os.path.join(self.output_dir, f"comparison_report_{timestamp}.txt")

            with open(report_path, "w", encoding="utf-8") as f:
                f.write("CRYPTOGRAPHIC ALGORITHMS COMPARISON REPORT\n")
                f.write("=" * 60 + "\n\n")
                f.write(comparison.to_string())
                f.write("\n\n")
                f.write("Includes: encryption time, decryption time, latency time, response time, message size, bit size.\n")

            print(f"\nReport saved to: {report_path}")

        return comparison


if __name__ == "__main__":
    comparison = CryptoComparison()

    csv_path = os.path.join(BASE_DIR, "results", "benchmark_results.csv")
    df = comparison.load_benchmark_data(csv_path)

    comparison.generate_all_graphs(df)
    comparison.create_summary_report(df)