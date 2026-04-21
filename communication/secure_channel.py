import hmac
import hashlib
import time
import threading
from typing import Tuple, Dict, Any, Optional


class SecureChannel:
    """Adds integrity and replay protection to IoT communication"""

    def __init__(
        self,
        shared_secret: bytes = b'iot_secret_key_2024',
        max_packet_age: int = 300,
        max_packet_size: int = 65536
    ):
        self.shared_secret = shared_secret
        self.max_packet_age = max_packet_age
        self.max_packet_size = max_packet_size
        self.seen_packets = set()
        self.lock = threading.Lock()

        self.stats = {
            "packets_created": 0,
            "packets_verified": 0,
            "packets_rejected": 0,
            "replay_attempts": 0,
            "expired_attempts": 0,
            "mac_failures": 0,
            "future_timestamps": 0
        }
        self.stats_lock = threading.Lock()

    def create_secure_packet(
        self,
        device_id: str,
        encrypted_data: bytes,
        sequence: int,
        extra_fields: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Create a secure packet with HMAC and timestamp
        """
        if len(encrypted_data) > self.max_packet_size:
            raise ValueError(
                f"Packet size {len(encrypted_data)} exceeds maximum {self.max_packet_size}"
            )

        timestamp = int(time.time())

        message = (
            device_id.encode("utf-8") +
            sequence.to_bytes(8, "big") +
            timestamp.to_bytes(8, "big") +
            encrypted_data
        )

        mac = hmac.new(self.shared_secret, message, hashlib.sha256).hexdigest()

        packet = {
            "device_id": device_id,
            "sequence": sequence,
            "timestamp": timestamp,
            "data": encrypted_data.hex(),
            "mac": mac,
            "version": "1.0"
        }

        if extra_fields:
            packet.update(extra_fields)

        with self.stats_lock:
            self.stats["packets_created"] += 1

        return packet

    def verify_packet(self, packet: Dict[str, Any]) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Verify packet integrity and replay protection

        Returns:
            (is_valid, message, metadata)
        """
        metadata = {}

        try:
            device_id = packet.get("device_id")
            sequence = packet.get("sequence")
            timestamp = packet.get("timestamp")
            encrypted_data_hex = packet.get("data")
            received_mac = packet.get("mac")

            missing = []
            if device_id is None or device_id == "":
                missing.append("device_id")
            if sequence is None:
                missing.append("sequence")
            if timestamp is None:
                missing.append("timestamp")
            if encrypted_data_hex is None or encrypted_data_hex == "":
                missing.append("data")
            if received_mac is None or received_mac == "":
                missing.append("mac")

            if missing:
                with self.stats_lock:
                    self.stats["packets_rejected"] += 1
                return False, f"Missing fields: {missing}", metadata

            try:
                sequence = int(sequence)
                timestamp = int(timestamp)
                encrypted_data = bytes.fromhex(encrypted_data_hex)
            except (ValueError, TypeError) as e:
                with self.stats_lock:
                    self.stats["packets_rejected"] += 1
                return False, f"Invalid data format: {e}", metadata

            if len(encrypted_data) > self.max_packet_size:
                with self.stats_lock:
                    self.stats["packets_rejected"] += 1
                return False, f"Packet too large: {len(encrypted_data)} bytes", metadata

            current_time = int(time.time())

            if current_time - timestamp > self.max_packet_age:
                with self.stats_lock:
                    self.stats["expired_attempts"] += 1
                    self.stats["packets_rejected"] += 1
                return False, f"Packet expired (age: {current_time - timestamp}s)", metadata

            if timestamp > current_time + 10:
                with self.stats_lock:
                    self.stats["future_timestamps"] += 1
                    self.stats["packets_rejected"] += 1
                return False, f"Future timestamp: {timestamp}", metadata

            packet_id = (device_id, sequence, timestamp)

            with self.lock:
                if packet_id in self.seen_packets:
                    with self.stats_lock:
                        self.stats["replay_attempts"] += 1
                        self.stats["packets_rejected"] += 1
                    return False, "Replay attack detected", metadata

                message = (
                    device_id.encode("utf-8") +
                    sequence.to_bytes(8, "big") +
                    timestamp.to_bytes(8, "big") +
                    encrypted_data
                )

                expected_mac = hmac.new(
                    self.shared_secret,
                    message,
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(received_mac, expected_mac):
                    with self.stats_lock:
                        self.stats["mac_failures"] += 1
                        self.stats["packets_rejected"] += 1
                    return False, "MAC verification failed", metadata

                self.seen_packets.add(packet_id)
                self._clean_old_packets(current_time)

            metadata = {
                "device_id": device_id,
                "sequence": sequence,
                "timestamp": timestamp,
                "age": current_time - timestamp
            }

            with self.stats_lock:
                self.stats["packets_verified"] += 1

            return True, "Valid", metadata

        except Exception as e:
            with self.stats_lock:
                self.stats["packets_rejected"] += 1
            return False, f"Verification error: {e}", metadata

    def _clean_old_packets(self, current_time: int):
        """Remove expired packet IDs to prevent memory growth"""
        cutoff = current_time - self.max_packet_age
        self.seen_packets = {
            pkt for pkt in self.seen_packets if pkt[2] > cutoff
        }

    def get_statistics(self) -> Dict[str, Any]:
        """Get channel statistics"""
        with self.stats_lock:
            return dict(self.stats)

    def clear_old_packets(self):
        """Manually trigger cleanup"""
        with self.lock:
            self._clean_old_packets(int(time.time()))