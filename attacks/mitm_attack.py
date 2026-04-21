"""
Man-in-the-Middle (MITM) attack demonstration for the IoT secure communication project.

Goal:
- Create valid packets
- Simulate various attacker tampering techniques
- Show that verification fails because HMAC no longer matches
"""

import os
import sys
import json
import copy
import time
from datetime import datetime
from typing import Dict, Any, List
import random

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from communication.secure_channel import SecureChannel


class MitmAttackDemo:
    """Demonstrate MITM tampering detection using HMAC verification."""

    def __init__(self, output_dir: str = "../results/attacks"):
        self.output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        self.channel = SecureChannel()
        self.demo_payloads = {
            "heart_rate": b'{"sensor":"heart_rate","value":82,"unit":"bpm"}',
            "temperature": b'{"sensor":"temperature","value":36.5,"unit":"C"}',
            "blood_pressure": b'{"sensor":"bp","systolic":120,"diastolic":80,"unit":"mmHg"}',
        }
        self.results = []

    def test_payload_tampering(self) -> Dict[str, Any]:
        """Test 1: Attacker modifies the payload data"""
        print("\n📋 Test 1: Payload Tampering")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_HR",
            encrypted_data=self.demo_payloads["heart_rate"],
            sequence=10,
            extra_fields={"cipher": "SIMON", "test": "payload_tamper"}
        )

        # Verify original
        valid_orig, msg_orig, _ = self.channel.verify_packet(copy.deepcopy(original))

        # Attacker modifies payload (changes heart rate from 82 to 120)
        tampered = copy.deepcopy(original)
        orig_data = bytes.fromhex(tampered["data"])
        
        # Simulate changing the value in the JSON
        tampered_data = orig_data.replace(b"82", b"120")
        if tampered_data == orig_data:
            # If replacement didn't work, append malicious data
            tampered_data = orig_data + b'&malicious=true'
        
        tampered["data"] = tampered_data.hex()

        valid_tampered, msg_tampered, _ = self.channel.verify_packet(tampered)

        return {
            "test_name": "Payload Tampering",
            "original_valid": valid_orig,
            "tampered_valid": valid_tampered,
            "tampered_message": msg_tampered,
            "attack_blocked": (valid_orig is True and valid_tampered is False),
            "tampering_type": "Modified sensor value"
        }

    def test_device_id_spoofing(self) -> Dict[str, Any]:
        """Test 2: Attacker tries to spoof device ID"""
        print("\n📋 Test 2: Device ID Spoofing")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payloads["temperature"],
            sequence=11,
            extra_fields={"cipher": "PRESENT", "test": "device_spoof"}
        )

        # Verify original
        valid_orig, msg_orig, _ = self.channel.verify_packet(copy.deepcopy(original))

        # Attacker changes device ID
        spoofed = copy.deepcopy(original)
        spoofed["device_id"] = "ATTACKER_FAKE_DEVICE"

        valid_spoofed, msg_spoofed, _ = self.channel.verify_packet(spoofed)

        return {
            "test_name": "Device ID Spoofing",
            "original_valid": valid_orig,
            "spoofed_valid": valid_spoofed,
            "spoofed_message": msg_spoofed,
            "attack_blocked": (valid_orig is True and valid_spoofed is False),
            "tampering_type": "Changed device ID"
        }

    def test_timestamp_manipulation(self) -> Dict[str, Any]:
        """Test 3: Attacker modifies timestamp"""
        print("\n📋 Test 3: Timestamp Manipulation")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_BP",
            encrypted_data=self.demo_payloads["blood_pressure"],
            sequence=12,
            extra_fields={"cipher": "SPECK", "test": "timestamp_manip"}
        )

        # Verify original
        valid_orig, msg_orig, _ = self.channel.verify_packet(copy.deepcopy(original))

        # Attacker changes timestamp (replay-style attack)
        timestamp_manip = copy.deepcopy(original)
        timestamp_manip["timestamp"] = original["timestamp"] - 3600  # Set to 1 hour ago

        valid_manip, msg_manip, _ = self.channel.verify_packet(timestamp_manip)

        return {
            "test_name": "Timestamp Manipulation",
            "original_valid": valid_orig,
            "manipulated_valid": valid_manip,
            "manipulated_message": msg_manip,
            "attack_blocked": (valid_orig is True and valid_manip is False),
            "tampering_type": "Modified timestamp"
        }

    def test_sequence_number_attack(self) -> Dict[str, Any]:
        """Test 4: Attacker modifies sequence number"""
        print("\n📋 Test 4: Sequence Number Attack")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_HR",
            encrypted_data=self.demo_payloads["heart_rate"],
            sequence=13,
            extra_fields={"cipher": "GIFT", "test": "sequence_attack"}
        )

        # Verify original
        valid_orig, msg_orig, _ = self.channel.verify_packet(copy.deepcopy(original))

        # Attacker changes sequence number
        seq_attack = copy.deepcopy(original)
        seq_attack["sequence"] = 999  # Different sequence number

        valid_seq, msg_seq, _ = self.channel.verify_packet(seq_attack)

        return {
            "test_name": "Sequence Number Attack",
            "original_valid": valid_orig,
            "sequence_attack_valid": valid_seq,
            "sequence_attack_message": msg_seq,
            "attack_blocked": (valid_orig is True and valid_seq is False),
            "tampering_type": "Modified sequence number"
        }

    def test_mac_stripping_attack(self) -> Dict[str, Any]:
        """Test 5: Attacker tries to remove MAC entirely"""
        print("\n📋 Test 5: MAC Stripping Attack")
        
        original = self.channel.create_secure_packet(
            device_id="PATIENT_001_TEMP",
            encrypted_data=self.demo_payloads["temperature"],
            sequence=14,
            extra_fields={"cipher": "PRESENT", "test": "mac_strip"}
        )

        # Verify original
        valid_orig, msg_orig, _ = self.channel.verify_packet(copy.deepcopy(original))

        # Attacker removes MAC field
        mac_strip = copy.deepcopy(original)
        del mac_strip["mac"]

        # Try to verify without MAC
        try:
            valid_strip, msg_strip, _ = self.channel.verify_packet(mac_strip)
        except Exception as e:
            valid_strip = False
            msg_strip = f"Exception: {e}"

        return {
            "test_name": "MAC Stripping Attack",
            "original_valid": valid_orig,
            "stripped_valid": valid_strip if isinstance(valid_strip, bool) else False,
            "stripped_message": str(msg_strip),
            "attack_blocked": (valid_orig is True and not valid_strip),
            "tampering_type": "Removed MAC field"
        }

    def test_replay_variant(self) -> Dict[str, Any]:
        """Test 6: Replay with same packet (already covered in replay_attack.py)"""
        print("\n📋 Test 6: MITM Replay Variant")
        
        packet = self.channel.create_secure_packet(
            device_id="PATIENT_001_BP",
            encrypted_data=self.demo_payloads["blood_pressure"],
            sequence=15,
            extra_fields={"cipher": "SPECK", "test": "mitm_replay"}
        )

        # First verification (should pass)
        first_valid, first_msg, _ = self.channel.verify_packet(packet)

        # Second verification of same packet (should fail - replay detection)
        second_valid, second_msg, _ = self.channel.verify_packet(packet)

        return {
            "test_name": "MITM Replay Variant",
            "first_attempt_valid": first_valid,
            "second_attempt_valid": second_valid,
            "second_message": second_msg,
            "attack_blocked": (first_valid is True and second_valid is False),
            "tampering_type": "Packet replay"
        }

    def run_all_tests(self) -> List[Dict[str, Any]]:
        """Run all MITM attack tests"""
        print("=" * 80)
        print("🛡️  MITM ATTACK TEST SUITE")
        print("=" * 80)

        # Reset channel for clean tests
        self.channel = SecureChannel()

        tests = [
            self.test_payload_tampering(),
            self.test_device_id_spoofing(),
            self.test_timestamp_manipulation(),
            self.test_sequence_number_attack(),
            self.test_mac_stripping_attack(),
            self.test_replay_variant(),
        ]

        self.results = tests
        return tests

    def run(self) -> Dict[str, Any]:
        """Run basic MITM attack demo (single test)"""
        result = self.test_payload_tampering()
        self.results = [result]
        self._save_result(result, "basic_mitm")
        return result

    def run_comprehensive(self) -> List[Dict[str, Any]]:
        """Run comprehensive MITM attack tests"""
        results = self.run_all_tests()
        
        # Save all results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        combined = {
            "test_suite": "MITM Attack Tests",
            "timestamp": datetime.now().isoformat(),
            "results": results,
            "summary": self._generate_summary(results),
            "secure_channel_stats": self.channel.get_statistics()
        }
        
        path = os.path.join(self.output_dir, f"mitm_test_suite_{timestamp}.json")
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
        """Print single test result"""
        print("\n" + "=" * 80)
        print(f"📊 MITM ATTACK RESULT: {result.get('test_name', 'Basic MITM')}")
        print("=" * 80)
        print(f"Tampering Type: {result.get('tampering_type', 'Unknown')}")
        print(f"Original Packet Valid: {'✅' if result.get('original_valid', False) else '❌'}")
        print(f"Tampered Packet Valid: {'✅' if result.get('tampered_valid', result.get('spoofed_valid', result.get('manipulated_valid', False))) else '❌'}")
        print(f"Attack Blocked: {'✅' if result.get('attack_blocked', False) else '❌'}")
        if 'tampered_message' in result:
            print(f"Message: {result['tampered_message']}")

    @staticmethod
    def print_summary(results: List[Dict[str, Any]]) -> None:
        """Print summary of all tests"""
        print("\n" + "=" * 80)
        print("📈 MITM ATTACK TEST SUMMARY")
        print("=" * 80)
        
        for i, result in enumerate(results, 1):
            status = "✅ PASS" if result.get("attack_blocked", False) else "❌ FAIL"
            print(f"\n{i}. {result['test_name']}: {status}")
            print(f"   Type: {result.get('tampering_type', 'Unknown')}")
            print(f"   Original: {'✓' if result.get('original_valid', False) else '✗'} | "
                  f"Tampered: {'✓' if result.get('tampered_valid', result.get('spoofed_valid', result.get('manipulated_valid', False))) else '✗'}")


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='MITM Attack Demo')
    parser.add_argument('--mode', choices=['basic', 'comprehensive'], default='basic',
                       help='Run basic or comprehensive tests')
    args = parser.parse_args()
    
    demo = MitmAttackDemo()
    
    if args.mode == 'comprehensive':
        print("🔬 Running comprehensive MITM attack tests...")
        results = demo.run_comprehensive()
        demo.print_summary(results)
    else:
        print("🎯 Running basic MITM attack demo...")
        result = demo.run()
        demo.print_result(result)
    
    print(f"\n📁 Results saved in: {demo.output_dir}")