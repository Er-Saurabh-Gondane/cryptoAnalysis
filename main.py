"""
IoT Cryptography Project - Main Orchestrator
=============================================
Complete pipeline for:
1. Sensor data simulation
2. Encryption with multiple algorithms
3. Secure communication
4. Performance benchmarking
5. Security analysis
6. Attack simulations
7. Report generation
"""

import os
import sys
import time
import argparse
import json
import threading
import traceback
from datetime import datetime
from typing import Dict, Any, Optional

import pandas as pd
import numpy as np

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import all modules
from communication.sender import SecureIoTDevice as IoTSender
from communication.receiver import IoTReceiver
from evaluation.benchmark import CryptoBenchmark
from attacks.attack_analyzer import AttackAnalyzer
from report.summary_report import SummaryReport
from report.statistics import CryptoStatistics


class IoTProjectOrchestrator:
    """Master orchestrator for the entire IoT cryptography project."""

    def __init__(self, output_dir: str = "results"):
        self.output_dir = output_dir
        self.results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.results_dir, exist_ok=True)

        self.dirs = {
            "benchmarks": os.path.join(self.results_dir, "benchmarks"),
            "attacks": os.path.join(self.results_dir, "attacks"),
            "reports": os.path.join(self.results_dir, "reports"),
            "graphs": os.path.join(self.results_dir, "graphs"),
            "communication": os.path.join(self.results_dir, "communication_logs"),
        }

        for dir_path in self.dirs.values():
            os.makedirs(dir_path, exist_ok=True)

        self.start_time = None
        self.end_time = None

    def print_header(self, title: str):
        print("\n" + "=" * 80)
        print(f"🚀 {title}")
        print("=" * 80)

    def print_subheader(self, title: str):
        print("\n" + "-" * 60)
        print(f"📌 {title}")
        print("-" * 60)

    def run_communication_demo(self, duration: int = 30, mode: str = "parallel") -> Dict[str, Any]:
        """Run communication demo with real-time sensor data."""
        if duration <= 0:
            raise ValueError("Duration must be greater than 0")

        self.print_subheader(f"Communication Demo ({mode} mode, {duration}s)")

        receiver = IoTReceiver("localhost", 9999)
        receiver_thread = threading.Thread(target=receiver.start, daemon=True)
        receiver_thread.start()

        time.sleep(2)  # simple startup wait

        iot_device = IoTSender("PATIENT_001", "localhost", 9999)
        iot_device.add_sensor("temperature", "PRESENT")
        iot_device.add_sensor("heart_rate", "SIMON")
        iot_device.add_sensor("blood_pressure", "SPECK")

        print(f"\n📡 Starting {mode} simulation...")

        try:
            if mode == "parallel":
                iot_device.run_parallel_simulation(duration=duration)
            else:
                iot_device.run_sequential_simulation()
        finally:
            receiver.stop()
            receiver_thread.join(timeout=2)

        return {
            "mode": mode,
            "duration": duration,
            "sensors": list(iot_device.senders.keys()),
            "status": "completed",
        }

    def run_benchmarks(self, quick: bool = False) -> pd.DataFrame:
        """Run comprehensive benchmarks."""
        self.print_subheader("Performance Benchmarks")

        benchmark = CryptoBenchmark(output_dir=self.dirs["benchmarks"])

        if quick:
            print("⚡ Running quick benchmarks (for testing)...")
            data_sizes = [16, 64, 256]
            iterations = 100
            throughput_iterations = 50
            cpu_duration = 1.0
        else:
            print("🔬 Running full benchmarks (this may take a few minutes)...")
            data_sizes = [16, 64, 256, 1024, 4096]
            iterations = 500
            throughput_iterations = 100
            cpu_duration = 2.0

        df = benchmark.run_comprehensive_benchmark(
            data_sizes=data_sizes,
            iterations=iterations,
            throughput_iterations=throughput_iterations,
            cpu_duration=cpu_duration,
        )

        benchmark.print_summary(df)
        return df

    def run_attack_simulations(self, comprehensive: bool = False) -> Dict[str, Any]:
        """Run all attack simulations."""
        self.print_subheader("Attack Simulations")

        analyzer = AttackAnalyzer(output_dir=self.dirs["attacks"])
        mode = "comprehensive" if comprehensive else "basic"

        print(f"🎯 Running {mode} attack analysis...")
        results = analyzer.analyze(mode=mode)
        analyzer.print_summary(results)

        return results

    def run_statistical_analysis(self, df: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        """Run advanced statistical analysis."""
        self.print_subheader("Statistical Analysis")

        stats = CryptoStatistics(output_dir=self.dirs["reports"])

        if df is None:
            try:
                df = stats.load_benchmark_data()
            except FileNotFoundError:
                print("⚠️ No benchmark data found. Running quick benchmarks...")
                df = self.run_benchmarks(quick=True)

        results = stats.run_comprehensive_analysis(df)
        stats.print_summary()

        return results

    def generate_final_report(self) -> Dict[str, str]:
        """Generate final comprehensive report."""
        self.print_subheader("Generating Final Report")

        report = SummaryReport(output_dir=self.dirs["reports"])
        report_paths = report.generate_report()

        print("\n✅ Reports generated:")
        print(f"  • HTML: {report_paths.get('html', 'Not generated')}")
        print(f"  • PDF: {report_paths.get('pdf', 'Not generated')}")

        return report_paths

    def print_timing(self):
        if self.start_time and self.end_time:
            elapsed = self.end_time - self.start_time
            mins = int(elapsed // 60)
            secs = elapsed % 60
            print("\n" + "⏱️  " * 20)
            print(f"Total Execution Time: {mins} minutes {secs:.2f} seconds")
            print("⏱️  " * 20)

    def run_complete_pipeline(self, args: argparse.Namespace):
        """Run the complete project pipeline."""
        self.start_time = time.time()
        benchmark_df = None

        self.print_header("IoT CRYPTOGRAPHY PROJECT - COMPLETE PIPELINE")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Mode: {'FULL' if not args.quick else 'QUICK TEST'}")

        pipeline_results = {
            "timestamp": datetime.now().isoformat(),
            "args": vars(args),
            "stages": {},
            "status": "running",
        }

        try:
            if args.communication:
                self.print_header("STAGE 1: IoT Communication Demo")
                comm_results = self.run_communication_demo(
                    duration=args.duration,
                    mode=args.comm_mode
                )
                pipeline_results["stages"]["communication"] = comm_results

            if args.benchmark:
                self.print_header("STAGE 2: Performance Benchmarks")
                benchmark_df = self.run_benchmarks(quick=args.quick)
                pipeline_results["stages"]["benchmark"] = {
                    "shape": benchmark_df.shape,
                    "columns": list(benchmark_df.columns),
                }

            if args.attacks:
                self.print_header("STAGE 3: Attack Simulations")
                attack_results = self.run_attack_simulations(
                    comprehensive=args.comprehensive_attacks
                )
                pipeline_results["stages"]["attacks"] = {
                    "mode": "comprehensive" if args.comprehensive_attacks else "basic",
                    "summary": attack_results.get("overall_summary", {}),
                }

            if args.statistics:
                self.print_header("STAGE 4: Statistical Analysis")
                stats_results = self.run_statistical_analysis(df=benchmark_df)
                pipeline_results["stages"]["statistics"] = {
                    "analyses": list(stats_results.keys())
                }

            if args.report:
                self.print_header("STAGE 5: Final Report Generation")
                report_paths = self.generate_final_report()
                pipeline_results["stages"]["report"] = report_paths

            self.end_time = time.time()
            pipeline_results["execution_time_seconds"] = self.end_time - self.start_time
            pipeline_results["status"] = "success"

        except KeyboardInterrupt:
            print("\n\n⚠️ Pipeline interrupted by user")
            self.end_time = time.time()
            pipeline_results["status"] = "interrupted"

        except Exception as e:
            print(f"\n❌ Error in pipeline: {e}")
            traceback.print_exc()
            self.end_time = time.time()
            pipeline_results["status"] = "failed"
            pipeline_results["error"] = str(e)

        finally:
            if self.end_time is None:
                self.end_time = time.time()

            pipeline_results["execution_time_seconds"] = self.end_time - self.start_time

            results_path = os.path.join(
                self.results_dir,
                f"pipeline_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
            with open(results_path, "w") as f:
                json.dump(pipeline_results, f, indent=2, default=str)

            if pipeline_results["status"] == "success":
                self.print_header("PIPELINE COMPLETED SUCCESSFULLY 🎉")
                print(f"📁 All results saved to: {self.results_dir}")

            self.print_timing()

    def run_interactive_menu(self):
        """Run interactive menu for selective execution."""
        while True:
            self.print_header("IoT CRYPTOGRAPHY PROJECT - INTERACTIVE MENU")
            print("1. Run Communication Demo")
            print("2. Run Performance Benchmarks")
            print("3. Run Attack Simulations")
            print("4. Run Statistical Analysis")
            print("5. Generate Final Report")
            print("6. Run Complete Pipeline")
            print("7. Quick Test (All stages, minimal)")
            print("0. Exit")

            choice = input("\nEnter your choice (0-7): ").strip()

            if choice == "1":
                duration = int(input("Enter duration (seconds) [30]: ") or "30")
                mode = input("Mode (parallel/sequential) [parallel]: ").strip() or "parallel"
                self.run_communication_demo(duration=duration, mode=mode)

            elif choice == "2":
                quick_input = input("Quick test? (y/n) [y]: ").strip().lower()
                quick = quick_input in ("", "y", "yes")
                self.run_benchmarks(quick=quick)

            elif choice == "3":
                comp_input = input("Comprehensive attacks? (y/n) [n]: ").strip().lower()
                comp = comp_input in ("y", "yes")
                self.run_attack_simulations(comprehensive=comp)

            elif choice == "4":
                self.run_statistical_analysis()

            elif choice == "5":
                self.generate_final_report()

            elif choice == "6":
                args = argparse.Namespace(
                    communication=True,
                    benchmark=True,
                    attacks=True,
                    statistics=True,
                    report=True,
                    quick=False,
                    comprehensive_attacks=True,
                    duration=30,
                    comm_mode="parallel",
                )
                self.run_complete_pipeline(args)

            elif choice == "7":
                args = argparse.Namespace(
                    communication=True,
                    benchmark=True,
                    attacks=True,
                    statistics=True,
                    report=True,
                    quick=True,
                    comprehensive_attacks=False,
                    duration=10,
                    comm_mode="parallel",
                )
                self.run_complete_pipeline(args)

            elif choice == "0":
                print("\n👋 Goodbye!")
                break

            else:
                print("\n⚠️ Invalid choice. Please enter a number between 0 and 7.")

            input("\nPress Enter to continue...")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="IoT Cryptography Project - Complete Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --quick
  python main.py --benchmark --report
  python main.py --communication --duration 60
  python main.py --all
  python main.py --interactive
        """
    )

    parser.add_argument("--all", action="store_true", help="Run complete pipeline")
    parser.add_argument("--interactive", action="store_true", help="Run interactive menu")
    parser.add_argument("--quick", action="store_true", help="Run quick test (minimal iterations)")

    parser.add_argument("--communication", action="store_true", help="Run communication demo")
    parser.add_argument("--benchmark", action="store_true", help="Run performance benchmarks")
    parser.add_argument("--attacks", action="store_true", help="Run attack simulations")
    parser.add_argument("--statistics", action="store_true", help="Run statistical analysis")
    parser.add_argument("--report", action="store_true", help="Generate final report")

    parser.add_argument("--duration", type=int, default=30, help="Communication demo duration (seconds)")
    parser.add_argument(
        "--comm-mode",
        choices=["parallel", "sequential"],
        default="parallel",
        help="Communication demo mode",
    )
    parser.add_argument(
        "--comprehensive-attacks",
        action="store_true",
        help="Run comprehensive attack tests",
    )

    args = parser.parse_args()
    orchestrator = IoTProjectOrchestrator()

    if args.interactive:
        orchestrator.run_interactive_menu()
        return

    if args.all or not any([args.communication, args.benchmark, args.attacks, args.statistics, args.report]):
        if not any([args.communication, args.benchmark, args.attacks, args.statistics, args.report]):
            args.communication = True
            args.benchmark = True
            args.attacks = True
            args.statistics = True
            args.report = True

    orchestrator.run_complete_pipeline(args)


if __name__ == "__main__":
    main()