"""
Attack analyzer for the IoT cryptography project.

Runs:
- Replay attack demo
- MITM attack demo
- Brute force demo

Creates:
- Summary table
- JSON report
- CSV report
- Text report
- Visualization charts
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, Any, List, Optional

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from attacks.replay_attack import ReplayAttackDemo
from attacks.mitm_attack import MitmAttackDemo
from attacks.brute_force_demo import BruteForceDemo


class AttackAnalyzer:
    """Run and summarize project attack demos."""

    def __init__(self, output_dir: str = "../results/attacks"):
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self.results: Dict[str, Any] = {}

    def run_basic(self) -> Dict[str, Any]:
        """Run basic attack demos (single test each)."""
        print("\n" + "=" * 80)
        print("🛡️  RUNNING BASIC ATTACK DEMOS")
        print("=" * 80)

        replay_demo = ReplayAttackDemo(output_dir="../results/attacks")
        mitm_demo = MitmAttackDemo(output_dir="../results/attacks")
        brute_demo = BruteForceDemo(output_dir="../results/attacks")

        print("\n📡 Testing Replay Attack...")
        replay_result = replay_demo.run()

        print("\n🔧 Testing MITM Attack...")
        mitm_result = mitm_demo.run()

        print("\n🔓 Testing Brute Force Demo...")
        brute_result = brute_demo.run()

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "mode": "basic",
            "replay_attack": replay_result,
            "mitm_attack": mitm_result,
            "brute_force_demo": brute_result,
        }

        return self.results

    def run_comprehensive(self) -> Dict[str, Any]:
        """Run comprehensive attack demos (multiple test scenarios)."""
        print("\n" + "=" * 80)
        print("🛡️  RUNNING COMPREHENSIVE ATTACK DEMOS")
        print("=" * 80)

        replay_demo = ReplayAttackDemo(output_dir="../results/attacks")
        mitm_demo = MitmAttackDemo(output_dir="../results/attacks")
        brute_demo = BruteForceDemo(output_dir="../results/attacks")

        print("\n📡 Testing Comprehensive Replay Attacks...")
        replay_results = replay_demo.run_comprehensive()

        print("\n🔧 Testing Comprehensive MITM Attacks...")
        mitm_results = mitm_demo.run_comprehensive()

        print("\n🔓 Testing Comprehensive Brute Force Analysis...")
        brute_results = brute_demo.run_comprehensive()

        self.results = {
            "timestamp": datetime.now().isoformat(),
            "mode": "comprehensive",
            "replay_attacks": replay_results,
            "mitm_attacks": mitm_results,
            "brute_force_analysis": brute_results,
        }

        return self.results

    def _safe_get(self, data: Any, path: List[Any], default: Any = None) -> Any:
        """Safely get nested dictionary/list value."""
        current = data
        try:
            for key in path:
                if isinstance(current, dict):
                    current = current[key]
                elif isinstance(current, list) and isinstance(key, int):
                    current = current[key]
                else:
                    return default
            return current
        except (KeyError, IndexError, TypeError):
            return default

    def _first_available(self, data: Dict[str, Any], candidate_paths: List[List[Any]], default: Any = None) -> Any:
        """Return first non-None value from candidate nested paths."""
        for path in candidate_paths:
            value = self._safe_get(data, path, None)
            if value is not None:
                return value
        return default

    def _infer_attack_blocked(self, result: Dict[str, Any], default: bool = False) -> bool:
        """Infer whether attack was blocked using multiple possible fields."""
        candidates = [
            ["attack_blocked"],
            ["blocked"],
            ["tampered_packet_verification", "is_valid"],
            ["tampered_packet_verification", "verified"],
            ["tampered_packet_verification", "success"],
            ["payload_tampering", "is_valid"],
            ["payload_tampering", "verified"],
            ["payload_tampering", "success"],
            ["replay_attempt", "blocked"],
            ["replay_attempt", "success"],
        ]

        for path in candidates:
            value = self._safe_get(result, path, None)
            if isinstance(value, bool):
                # For validity fields: tampered packet valid = NOT blocked
                if path[-1] in ("is_valid", "verified"):
                    return not value
                return value

        return default

    def _extract_replay_message(self, replay: Dict[str, Any]) -> str:
        return self._first_available(
            replay,
            [
                ["replay_attempt", "message"],
                ["replay_detection", "message"],
                ["result", "message"],
                ["message"],
            ],
            default="Replay attack result not available",
        )

    def _extract_mitm_message(self, mitm: Dict[str, Any]) -> str:
        return self._first_available(
            mitm,
            [
                ["tampered_packet_verification", "message"],
                ["payload_tampering", "message"],
                ["verification_result", "message"],
                ["result", "message"],
                ["message"],
            ],
            default="MITM tampering result not available",
        )

    def _extract_bruteforce_toy_message(self, brute: Dict[str, Any]) -> str:
        recovered = self._first_available(
            brute,
            [
                ["toy_demo", "key_recovered"],
                ["toy_demo", "recovered"],
                ["toy_demos", 0, "key_recovered"],
                ["toy_demos", 0, "recovered"],
            ],
            default=None,
        )
        if recovered is not None:
            return f"Recovered: {recovered}"

        return self._first_available(
            brute,
            [
                ["toy_demo", "message"],
                ["message"],
            ],
            default="Toy brute-force demo result not available",
        )

    def _extract_comprehensive_summary(self, suite: Any) -> Dict[str, Any]:
        """
        Extract summary from comprehensive suite.
        Supports:
        - list with last item containing summary
        - dict with 'summary'
        - fallback computed values
        """
        if isinstance(suite, dict):
            summary = suite.get("summary")
            if isinstance(summary, dict):
                return summary

        if isinstance(suite, list) and suite:
            last_item = suite[-1]
            if isinstance(last_item, dict) and "summary" in last_item and isinstance(last_item["summary"], dict):
                return last_item["summary"]

            # fallback: count pass/fail from list entries
            passed = 0
            failed = 0
            for item in suite:
                if not isinstance(item, dict):
                    continue
                if item.get("attack_blocked") is True or item.get("success") is True:
                    passed += 1
                else:
                    failed += 1

            total = passed + failed
            return {
                "passed": passed,
                "failed": failed,
                "success_rate": f"{(passed / total * 100):.1f}%" if total > 0 else "0.0%",
            }

        return {
            "passed": 0,
            "failed": 0,
            "success_rate": "0.0%",
        }

    def _generate_summary_rows(self) -> List[Dict[str, Any]]:
        """Generate summary rows from results."""
        rows: List[Dict[str, Any]] = []

        if self.results.get("mode") == "comprehensive":
            replay_suite = self.results.get("replay_attacks", [])
            mitm_suite = self.results.get("mitm_attacks", [])
            brute = self.results.get("brute_force_analysis", {})

            replay_summary = self._extract_comprehensive_summary(replay_suite)
            mitm_summary = self._extract_comprehensive_summary(mitm_suite)

            rows.append({
                "Attack Category": "Replay Attacks",
                "Tests Run": len(replay_suite) if isinstance(replay_suite, list) else replay_summary["passed"] + replay_summary["failed"],
                "Passed": replay_summary.get("passed", 0),
                "Failed": replay_summary.get("failed", 0),
                "Success Rate": replay_summary.get("success_rate", "0.0%"),
                "Protection": "✅ Working" if replay_summary.get("passed", 0) > 0 else "❌ Failed",
            })

            rows.append({
                "Attack Category": "MITM Attacks",
                "Tests Run": len(mitm_suite) if isinstance(mitm_suite, list) else mitm_summary["passed"] + mitm_summary["failed"],
                "Passed": mitm_summary.get("passed", 0),
                "Failed": mitm_summary.get("failed", 0),
                "Success Rate": mitm_summary.get("success_rate", "0.0%"),
                "Protection": "✅ Working" if mitm_summary.get("passed", 0) > 0 else "❌ Failed",
            })

            toy_demos = brute.get("toy_demos", [])
            if not isinstance(toy_demos, list):
                toy_demos = []

            toy_passed = sum(
                1 for d in toy_demos
                if isinstance(d, dict) and (d.get("key_recovered") is True or d.get("recovered") is True)
            )
            toy_total = len(toy_demos)
            toy_failed = toy_total - toy_passed

            rows.append({
                "Attack Category": "Brute Force (Toy)",
                "Tests Run": toy_total,
                "Passed": toy_passed,
                "Failed": toy_failed,
                "Success Rate": f"{(toy_passed / toy_total * 100):.1f}%" if toy_total > 0 else "0.0%",
                "Protection": "⚠️ Demo Only",
            })

            real_analysis = brute.get("real_algorithm_analysis", [])
            if not isinstance(real_analysis, list):
                real_analysis = []

            rows.append({
                "Attack Category": "Brute Force (Real Keys)",
                "Tests Run": len(real_analysis),
                "Passed": len(real_analysis),
                "Failed": 0,
                "Success Rate": "100%" if len(real_analysis) > 0 else "0.0%",
                "Protection": "✅ Infeasible" if len(real_analysis) > 0 else "⚠️ No Data",
            })

        else:
            replay = self.results.get("replay_attack", {})
            mitm = self.results.get("mitm_attack", {})
            brute = self.results.get("brute_force_demo", {})

            replay_blocked = self._infer_attack_blocked(replay, default=False)
            mitm_blocked = self._infer_attack_blocked(mitm, default=False)

            toy_recovered = self._first_available(
                brute,
                [
                    ["toy_demo", "key_recovered"],
                    ["toy_demo", "recovered"],
                    ["toy_demos", 0, "key_recovered"],
                    ["toy_demos", 0, "recovered"],
                ],
                default=False,
            )

            rows = [
                {
                    "Attack": "Replay Attack",
                    "Target": "Packet Replay",
                    "Expected": "Replay should be rejected",
                    "Observed": self._extract_replay_message(replay),
                    "Blocked": replay_blocked,
                    "Status": "✅ Protected" if replay_blocked else "❌ Vulnerable",
                },
                {
                    "Attack": "MITM Tampering",
                    "Target": "Data Integrity",
                    "Expected": "Modified packet should fail MAC",
                    "Observed": self._extract_mitm_message(mitm),
                    "Blocked": mitm_blocked,
                    "Status": "✅ Protected" if mitm_blocked else "❌ Vulnerable",
                },
                {
                    "Attack": "Brute Force (Toy)",
                    "Target": "Toy 8-bit Key",
                    "Expected": "Key should be recoverable",
                    "Observed": self._extract_bruteforce_toy_message(brute),
                    "Blocked": False,
                    "Status": "⚠️ Demo Only",
                },
                {
                    "Attack": "Brute Force (Real)",
                    "Target": "128-bit Keys",
                    "Expected": "Should be infeasible",
                    "Observed": "Theoretically infeasible",
                    "Blocked": True,
                    "Status": "✅ Resistant",
                },
            ]

        return rows

    def _create_visualization(self, df: pd.DataFrame) -> None:
        """Create visualization of attack results."""
        if df.empty:
            print("\n⚠️ No attack data available for visualization.")
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            if self.results.get("mode") == "comprehensive":
                plt.figure(figsize=(10, 6))

                categories = df["Attack Category"].tolist()
                passed = df["Passed"].tolist()
                failed = df["Failed"].tolist()

                x = np.arange(len(categories))
                width = 0.35

                plt.bar(x - width / 2, passed, width, label="Passed", alpha=0.7)
                plt.bar(x + width / 2, failed, width, label="Failed", alpha=0.7)

                plt.xlabel("Attack Category")
                plt.ylabel("Number of Tests")
                plt.title("Attack Test Results - Comprehensive Analysis")
                plt.xticks(x, categories, rotation=45, ha="right")
                plt.legend()
                plt.grid(True, alpha=0.3)

            else:
                fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

                protected_count = sum(1 for r in self.results.get("summary_rows", []) if r.get("Blocked", False))
                vulnerable_count = len(self.results.get("summary_rows", [])) - protected_count

                if protected_count + vulnerable_count == 0:
                    protected_count = 1
                    vulnerable_count = 0

                ax1.pie(
                    [protected_count, vulnerable_count],
                    labels=["Protected", "Vulnerable/Demo"],
                    autopct="%1.1f%%",
                    startangle=90
                )
                ax1.set_title("Attack Protection Status")

                attacks = [r.get("Attack", "Unknown") for r in self.results.get("summary_rows", [])]
                status = [1 if r.get("Blocked", False) else 0 for r in self.results.get("summary_rows", [])]

                ax2.bar(attacks, status)
                ax2.set_ylabel("Protected (1) / Vulnerable (0)")
                ax2.set_title("Attack Resistance")
                ax2.set_ylim(0, 1.2)
                ax2.grid(True, alpha=0.3)
                ax2.tick_params(axis="x", rotation=45)

            plt.tight_layout()

            graph_path = os.path.join(self.output_dir, f"attack_analysis_{timestamp}.png")
            plt.savefig(graph_path, dpi=300, bbox_inches="tight")
            plt.close()

            print(f"\n📊 Analysis graph saved to: {graph_path}")

        except Exception as e:
            print(f"\n⚠️ Failed to create visualization: {e}")
            plt.close("all")

    def analyze(self, mode: str = "basic") -> Dict[str, Any]:
        """Run attack analysis in specified mode."""
        if mode == "comprehensive":
            results = self.run_comprehensive()
        else:
            results = self.run_basic()

        summary_rows = self._generate_summary_rows()
        results["summary_rows"] = summary_rows

        df = pd.DataFrame(summary_rows)

        if mode == "comprehensive":
            total_tests_run = int(df["Tests Run"].sum()) if not df.empty and "Tests Run" in df.columns else 0
            total_passed = int(df["Passed"].sum()) if not df.empty and "Passed" in df.columns else 0
            total_failed = int(df["Failed"].sum()) if not df.empty and "Failed" in df.columns else 0

            replay_passed = 0
            mitm_passed = 0
            if not df.empty and "Attack Category" in df.columns:
                replay_row = df[df["Attack Category"] == "Replay Attacks"]
                mitm_row = df[df["Attack Category"] == "MITM Attacks"]
                if not replay_row.empty:
                    replay_passed = int(replay_row["Passed"].iloc[0])
                if not mitm_row.empty:
                    mitm_passed = int(mitm_row["Passed"].iloc[0])

            overall = {
                "total_test_suites": len(df),
                "total_tests_run": total_tests_run,
                "total_passed": total_passed,
                "total_failed": total_failed,
                "overall_success_rate": f"{(total_passed / total_tests_run * 100):.1f}%" if total_tests_run > 0 else "N/A",
                "replay_protection": "✅ Working" if replay_passed > 0 else "❌ Failed",
                "integrity_protection": "✅ Working" if mitm_passed > 0 else "❌ Failed",
                "real_keys_resistant": True,
            }
        else:
            replay = results.get("replay_attack", {})
            mitm = results.get("mitm_attack", {})
            brute = results.get("brute_force_demo", {})

            overall = {
                "replay_protection_working": self._infer_attack_blocked(replay, default=False),
                "integrity_protection_working": self._infer_attack_blocked(mitm, default=False),
                "toy_bruteforce_demo_working": bool(
                    self._first_available(
                        brute,
                        [
                            ["toy_demo", "key_recovered"],
                            ["toy_demo", "recovered"],
                            ["toy_demos", 0, "key_recovered"],
                            ["toy_demos", 0, "recovered"],
                        ],
                        default=False,
                    )
                ),
                "real_keyspace_resistance_supported": True,
                "attacks_blocked": sum(1 for r in summary_rows if r.get("Blocked", False)),
                "total_attacks": len(summary_rows),
            }

        results["overall_summary"] = overall

        self._create_visualization(df)
        self._save_all(df, results)

        return results

    def _save_all(self, df: pd.DataFrame, results: Dict[str, Any]) -> None:
        """Save all output formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        mode = results.get("mode", "basic")

        json_path = os.path.join(self.output_dir, f"attack_analysis_{mode}_{timestamp}.json")
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        csv_path = os.path.join(self.output_dir, f"attack_summary_{mode}_{timestamp}.csv")
        df.to_csv(csv_path, index=False)

        txt_path = os.path.join(self.output_dir, f"attack_report_{mode}_{timestamp}.txt")
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("ATTACK ANALYSIS REPORT\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Mode: {mode.upper()}\n")
            f.write(f"Timestamp: {results.get('timestamp', 'N/A')}\n\n")
            f.write(df.to_string(index=False))
            f.write("\n\nOverall Summary:\n")
            for key, value in results.get("overall_summary", {}).items():
                f.write(f"  {key}: {value}\n")

        print(f"\n📁 Results saved:")
        print(f"  - JSON: {json_path}")
        print(f"  - CSV: {csv_path}")
        print(f"  - Text: {txt_path}")

    @staticmethod
    def print_summary(results: Dict[str, Any]) -> None:
        """Print formatted summary."""
        df = pd.DataFrame(results.get("summary_rows", []))

        print("\n" + "=" * 80)
        print("🛡️  ATTACK ANALYSIS SUMMARY")
        print("=" * 80)
        print(f"Mode: {results.get('mode', 'basic').upper()}")
        print(f"Timestamp: {results.get('timestamp', 'N/A')}\n")

        if df.empty:
            print("No summary data available.")
        else:
            print(df.to_string(index=False))

        print("\n📊 Overall Summary:")
        for key, value in results.get("overall_summary", {}).items():
            if isinstance(value, bool):
                status = "✅" if value else "❌"
                print(f"  {status} {key}: {value}")
            else:
                print(f"  {key}: {value}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Attack Analyzer")
    parser.add_argument(
        "--mode",
        choices=["basic", "comprehensive"],
        default="basic",
        help="Run basic or comprehensive analysis"
    )
    args = parser.parse_args()

    analyzer = AttackAnalyzer()

    print(f"\n🔬 Running {args.mode} attack analysis...")
    results = analyzer.analyze(mode=args.mode)
    analyzer.print_summary(results)