"""
Replay attack demonstration for the IoT secure communication project.

Goal:
- Create one valid packet
- Verify it once (should pass)
- Replay the exact same packet
- Verify again (should fail due to replay protection)

Also tests:
- Multiple replay attempts
- Replay with modified fields
- Sequence number reuse
"""

import os
import sys
import json
import time
from datetime import datetime
from typing import Dict, Any, List
import copy

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.secure_channel import SecureChannel


class ReplayAttackDemo:
    """Demonstrate replay attack detection using SecureChannel."""

    def __init__(self, output_dir: str = "../results/attacks"):
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.channel = SecureChannel()
        self.demo_payload = b'{"sensor":"temperature","value":36.5,"unit":"C"}'
        self.results = []

    def test_basic_replay(self) -> Dict[str, Any]:
        """Test 1: Basic replay attack - same packet twice"""
        print("\n📋 Test 1: Basic Replay Attack")
        
        packet = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payload,
            sequence=1,
            extra_fields={"cipher": "SPECK", "test": "basic_replay"}
        )

        first_valid, first_msg, first_meta = self.channel.verify_packet(packet)
        replay_valid, replay_msg, replay_meta = self.channel.verify_packet(packet)

        return {
            "test_name": "Basic Replay",
            "first_attempt": {
                "valid": first_valid,
                "message": first_msg,
            },
            "replay_attempt": {
                "valid": replay_valid,
                "message": replay_msg,
            },
            "attack_blocked": (first_valid is True and replay_valid is False),
            "expected_behavior": "First packet accepted, replayed packet rejected"
        }

    def test_sequence_reuse(self) -> Dict[str, Any]:
        """Test 2: Same sequence number with different timestamp"""
        print("\n📋 Test 2: Sequence Number Reuse")
        
        # First packet
        packet1 = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payload,
            sequence=2,
            extra_fields={"cipher": "SPECK", "test": "sequence_reuse"}
        )
        
        # Wait 1 second to ensure different timestamp
        time.sleep(1)
        
        # Second packet with same sequence but different timestamp
        packet2 = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payload,
            sequence=2,  # Same sequence!
            extra_fields={"cipher": "SPECK", "test": "sequence_reuse"}
        )

        valid1, msg1, _ = self.channel.verify_packet(packet1)
        valid2, msg2, _ = self.channel.verify_packet(packet2)

        return {
            "test_name": "Sequence Reuse",
            "first_packet": {
                "valid": valid1,
                "message": msg1,
                "sequence": 2,
            },
            "second_packet": {
                "valid": valid2,
                "message": msg2,
                "sequence": 2,
            },
            "attack_blocked": (valid1 is True and valid2 is False),
            "expected_behavior": "Different timestamps shouldn't allow sequence reuse"
        }

    def test_tampered_replay(self) -> Dict[str, Any]:
        """Test 3: Replay with modified fields"""
        print("\n📋 Test 3: Tampered Replay Attack")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payload,
            sequence=3,
            extra_fields={"cipher": "SPECK", "test": "tampered"}
        )

        # Verify original (should pass)
        valid_orig, msg_orig, _ = self.channel.verify_packet(original)

        # Create tampered copy
        tampered = copy.deepcopy(original)
        tampered["device_id"] = "ATTACKER_DEVICE"  # Change device ID
        tampered["data"] = b"MALICIOUS_DATA".hex()  # Change data

        # Try to verify tampered packet
        valid_tampered, msg_tampered, _ = self.channel.verify_packet(tampered)

        return {
            "test_name": "Tampered Replay",
            "original_valid": valid_orig,
            "tampered_valid": valid_tampered,
            "tampered_message": msg_tampered,
            "attack_blocked": (valid_orig is True and valid_tampered is False),
            "expected_behavior": "Tampered packet should fail MAC verification"
        }

    def test_mass_replay(self, count: int = 5) -> Dict[str, Any]:
        """Test 4: Multiple replay attempts"""
        print(f"\n📋 Test 4: Mass Replay ({count} attempts)")
        
        packet = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payload,
            sequence=4,
            extra_fields={"cipher": "SPECK", "test": "mass_replay"}
        )

        # First verification (should pass)
        first_valid, first_msg, _ = self.channel.verify_packet(packet)

        # Multiple replay attempts
        replay_results = []
        for i in range(count):
            valid, msg, _ = self.channel.verify_packet(packet)
            replay_results.append({"attempt": i+1, "valid": valid, "message": msg})

        return {
            "test_name": f"Mass Replay ({count} attempts)",
            "first_attempt_valid": first_valid,
            "replay_results": replay_results,
            "all_replays_blocked": all(not r["valid"] for r in replay_results),
            "expected_behavior": "All replay attempts should be blocked"
        }

    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all replay attack tests"""
        print("=" * 80)
        print("🛡️  REPLAY ATTACK TEST SUITE")
        print("=" * 80)

        # Reset channel for clean tests
        self.channel = SecureChannel()

        tests = [
            self.test_basic_replay(),
            self.test_sequence_reuse(),
            self.test_tampered_replay(),
            self.test_mass_replay(5)
        ]

        self.results = tests
        return tests

    def run(self) -> Dict[str, Any]:
        """Run basic replay attack demo (single test)"""
        result = self.test_basic_replay()
        self.results = [result]
        self._save_result(result, "basic_replay")
        return result

    def run_comprehensive(self) -> List[Dict[str, Any]]:
        """Run comprehensive replay attack tests"""
        results = self.run_all_tests()
        
        # Save all results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        combined = {
            "test_suite": "Replay Attack Tests",
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": self._generate_summary(results),
            "secure_channel_stats": self.channel.get_statistics()
        }
        
        path = os.path.join(self.output_dir, f"replay_test_suite_{timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2)
        
        return results

    def _generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary of all tests"""
        total_tests = len(results)
        passed = sum(1 for r in results if r.get("attack_blocked", False))
        
        return {
            "total_tests": total_tests,
            "passed": passed,
            "failed": total_tests - passed,
            "success_rate": f"{(passed/total_tests)*100:.1f}%" if total_tests > 0 else "N/A"
        }

    def _save_result(self, result: Dict[str, Any], test_name: str) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(self.output_dir, f"{test_name}_{timestamp}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

    @staticmethod
    def print_result(result: Dict[str, Any]) -> None:
        print("\n" + "=" * 80)
        print("📊 REPLAY ATTACK RESULT")
        print("=" * 80)
        print(f"Test: {result.get('test_name', 'Basic Replay')}")
        print(f"First Attempt: {'✅' if result['first_attempt']['valid'] else '❌'} - {result['first_attempt']['message']}")
        print(f"Replay Attempt: {'✅' if result['replay_attempt']['valid'] else '❌'} - {result['replay_attempt']['message']}")
        print(f"Attack Blocked: {'✅' if result['attack_blocked'] else '❌'}")
        print(f"Expected: {result['expected_behavior']}")

    @staticmethod
    def print_summary(results: List[Dict[str, Any]]) -> None:
        """Print summary of all tests"""
        print("\n" + "=" * 80)
        print("📈 REPLAY ATTACK TEST SUMMARY")
        print("=" * 80)
        
        for i, result in enumerate(results, 1):
            status = "✅ PASS" if result.get("attack_blocked", False) else "❌ FAIL"
            print(f"\n{i}. {result['test_name']}: {status}")
            if "first_attempt" in result and "replay_attempt" in result:
                print(f"   First: {result['first_attempt']['valid']} | Replay: {result['replay_attempt']['valid']}")
            elif "all_replays_blocked" in result:
                print(f"   All replays blocked: {result['all_replays_blocked']}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Replay Attack Demo')
    parser.add_argument('--mode', choices=['basic', 'comprehensive'], default='basic',
                       help='Run basic or comprehensive tests')
    args = parser.parse_args()
    
    demo = ReplayAttackDemo()
    
    if args.mode == 'comprehensive':
        print("🔬 Running comprehensive replay attack tests...")
        results = demo.run_comprehensive()
        demo.print_summary(results)
    else:
        print("🎯 Running basic replay attack demo...")
        result = demo.run()
        demo.print_result(result)
    
    print(f"\n📁 Results saved in: {demo.output_dir}")