"""
Sender module for IoT devices
Encrypts and sends sensor data securely
"""

import socket
import json
import time
import threading
from typing import Dict, Any, Optional, Callable
import sys
import os
import signal

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto.present_cipher import PresentCipher
from crypto.simon_cipher import SimonCipher
from crypto.speck_cipher import SpeckCipher
from crypto.gift_cipher import GiftCipher
from crypto.tinyjambu_cipher import TinyJambuCipher
from communication.secure_channel import SecureChannel


class IoTSender:
    """IoT Device Sender - Encrypts and transmits sensor data"""

    DEMO_KEY = 0x0123456789ABCDEF0123456789ABCDEF
    PING_INTERVAL = 30

    def __init__(self, device_id: str, cipher_type: str = "SIMON",
                 server_host: str = "localhost", server_port: int = 9999,
                 on_disconnect: Optional[Callable] = None):
        self.device_id = device_id
        self.cipher_type = cipher_type.upper()
        self.server_host = server_host
        self.server_port = server_port
        self.on_disconnect = on_disconnect

        self.socket = None
        self.socket_file = None
        self.cipher = self._initialize_cipher()
        self.secure_channel = SecureChannel()

        self.session_key = self._generate_session_key()
        self.sequence_number = 0
        self.connected = False
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5
        self.reconnect_delay = 2
        self.running = False

        self.send_lock = threading.Lock()
        self.connection_lock = threading.Lock()
        self.ping_thread = None

        self.stats = {
            "packets_sent": 0,
            "bytes_sent": 0,
            "reconnects": 0,
            "send_failures": 0
        }
        self.stats_lock = threading.Lock()

        self.cipher.key_schedule(self.session_key)

        try:
            signal.signal(signal.SIGINT, self.signal_handler)
        except Exception:
            pass

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n[{self.device_id}] Received interrupt. Disconnecting...")
        self.disconnect()

    def _initialize_cipher(self):
        if self.cipher_type == "PRESENT":
            return PresentCipher(128)
        elif self.cipher_type == "SIMON":
            return SimonCipher("64/128")
        elif self.cipher_type == "SPECK":
            return SpeckCipher("64/128")
        elif self.cipher_type == "GIFT":
            return GiftCipher()
        elif self.cipher_type == "TINYJAMBU":
            return TinyJambuCipher(128, "128")
        else:
            raise ValueError(f"Unsupported cipher: {self.cipher_type}")

    def _generate_session_key(self) -> int:
        """Demo key generation"""
        return self.DEMO_KEY

    def _get_key_size_for_handshake(self) -> int:
        """Safe key size reporting"""
        return getattr(self.cipher, "key_size", 128)

    def connect(self) -> bool:
        """Connect to receiver server"""
        with self.connection_lock:
            try:
                self.disconnect()

                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(10.0)
                self.socket.connect((self.server_host, self.server_port))
                self.socket_file = self.socket.makefile("w", encoding="utf-8")

                print(f"[{self.device_id}] Connected to server at {self.server_host}:{self.server_port}")

                handshake = {
                    "device_id": self.device_id,
                    "cipher_type": self.cipher_type,
                    "key_size": self._get_key_size_for_handshake(),
                    "timestamp": time.time(),
                    "version": "1.0"
                }

                self.socket_file.write(json.dumps(handshake) + "\n")
                self.socket_file.flush()

                self.connected = True
                self.reconnect_attempts = 0
                self.running = True

                if self.ping_thread is None or not self.ping_thread.is_alive():
                    self.ping_thread = threading.Thread(target=self._ping_worker, daemon=True)
                    self.ping_thread.start()

                return True

            except Exception as e:
                print(f"[{self.device_id}] Connection failed: {e}")
                self.disconnect()
                return False

    def disconnect(self):
        """Disconnect from server"""
        was_connected = self.connected
        self.running = False
        self.connected = False

        try:
            if self.socket_file:
                self.socket_file.close()
        except Exception:
            pass

        try:
            if self.socket:
                self.socket.close()
        except Exception:
            pass

        self.socket_file = None
        self.socket = None

        if was_connected:
            print(f"[{self.device_id}] Disconnected")
            if self.on_disconnect:
                self.on_disconnect(self.device_id)

    def ensure_connection(self) -> bool:
        """Ensure we have an active connection, reconnect if needed"""
        if self.connected and self.socket and self.socket_file:
            return True

        if self.reconnect_attempts < self.max_reconnect_attempts:
            delay = self.reconnect_delay * (self.reconnect_attempts + 1)
            print(
                f"[{self.device_id}] Attempting to reconnect... "
                f"(Attempt {self.reconnect_attempts + 1}/{self.max_reconnect_attempts}, delay: {delay}s)"
            )

            time.sleep(delay)
            self.reconnect_attempts += 1

            with self.stats_lock:
                self.stats["reconnects"] += 1

            return self.connect()

        print(f"[{self.device_id}] Max reconnection attempts reached")
        return False

    def _ping_worker(self):
        """Background thread to send keep-alive pings"""
        while self.running:
            time.sleep(self.PING_INTERVAL)

            if not self.running:
                break

            if self.connected:
                try:
                    ping_data = {
                        "type": "ping",
                        "timestamp": time.time(),
                        "device": self.device_id
                    }
                    self.send_data(ping_data, is_ping=True)
                except Exception:
                    pass

    def encrypt_sensor_data(self, sensor_data: Dict[str, Any], sequence: int) -> bytes:
        """Encrypt sensor data for transmission"""
        packet = {
            "device_id": self.device_id,
            "sequence": sequence,
            "timestamp": time.time(),
            "data": sensor_data
        }

        json_data = json.dumps(packet)
        data_bytes = json_data.encode("utf-8")

        if self.cipher_type == "TINYJAMBU":
            nonce = sequence & 0xFFFFFFFFFFFFFFFFFFFFFFFF
            encrypted = self.cipher.encrypt(data_bytes, nonce)
        else:
            encrypted = self.cipher.encrypt(data_bytes)

        return encrypted

    def send_data(self, sensor_data: Dict[str, Any], is_ping: bool = False) -> bool:
        """Send encrypted sensor data to receiver"""
        with self.send_lock:
            if not self.ensure_connection():
                return False

            try:
                seq = self.sequence_number
                encrypted_data = self.encrypt_sensor_data(sensor_data, seq)
                self.sequence_number += 1

                extra_fields = {
                    "cipher": self.cipher_type,
                    "length": len(encrypted_data),
                    "ping": is_ping
                }

                packet = self.secure_channel.create_secure_packet(
                    device_id=self.device_id,
                    encrypted_data=encrypted_data,
                    sequence=seq,
                    extra_fields=extra_fields
                )

                self.socket_file.write(json.dumps(packet) + "\n")
                self.socket_file.flush()

                with self.stats_lock:
                    self.stats["packets_sent"] += 1
                    self.stats["bytes_sent"] += len(encrypted_data)

                if not is_ping:
                    print(f"[{self.device_id}] Sent {len(encrypted_data)} bytes (Seq: {seq})")

                return True

            except BrokenPipeError:
                print(f"[{self.device_id}] Connection broken")
                self.connected = False
                with self.stats_lock:
                    self.stats["send_failures"] += 1
                return False

            except Exception as e:
                print(f"[{self.device_id}] Send failed: {e}")
                self.connected = False
                with self.stats_lock:
                    self.stats["send_failures"] += 1
                return False

    def simulate_sensor_stream(self, sensor_type: str,
                               duration_seconds: int = 30,
                               interval_seconds: float = 1.0,
                               callback: Optional[Callable] = None):
        """
        Simulate continuous sensor data stream
        """
        from sensors.temp_sensor import TemperatureSensor
        from sensors.heart_sensor import HeartRateSensor
        from sensors.bp_sensor import BloodPressureSensor

        print(f"[{self.device_id}] Starting {sensor_type} simulation for {duration_seconds}s")

        if sensor_type == "temperature":
            sensor = TemperatureSensor(f"{self.device_id}_TEMP")
        elif sensor_type == "heart_rate":
            sensor = HeartRateSensor(f"{self.device_id}_HR")
        elif sensor_type == "blood_pressure":
            sensor = BloodPressureSensor(f"{self.device_id}_BP")
        else:
            raise ValueError(f"Unknown sensor type: {sensor_type}")

        start_time = time.time()
        readings_count = 0
        consecutive_failures = 0
        max_consecutive_failures = 3

        while time.time() - start_time < duration_seconds:
            if not self.running:
                break

            try:
                data = sensor.read_sensor()

                if self.send_data(data):
                    readings_count += 1
                    consecutive_failures = 0

                    if callback:
                        callback(sensor_type, data, readings_count)
                else:
                    consecutive_failures += 1

                if consecutive_failures >= max_consecutive_failures:
                    print(f"[{self.device_id}] Too many failures, attempting to reconnect...")
                    if not self.ensure_connection():
                        print(f"[{self.device_id}] Cannot recover connection")
                        break
                    consecutive_failures = 0

                time.sleep(interval_seconds)

            except Exception as e:
                print(f"[{self.device_id}] Simulation error: {e}")
                consecutive_failures += 1
                time.sleep(interval_seconds)

        print(f"[{self.device_id}] Simulation complete. Sent {readings_count} readings")

    def get_statistics(self) -> Dict[str, Any]:
        """Get sender statistics"""
        with self.stats_lock:
            stats = dict(self.stats)

        stats["sequence"] = self.sequence_number
        stats["connected"] = self.connected
        stats["cipher"] = self.cipher_type
        stats["secure_channel_stats"] = self.secure_channel.get_statistics()
        return stats


class SecureIoTDevice:
    """High-level IoT device with multiple sensors"""

    def __init__(self, device_id: str, server_host: str = "localhost",
                 server_port: int = 9999):
        self.device_id = device_id
        self.senders = {}
        self.server_host = server_host
        self.server_port = server_port
        self.running = False

    def add_sensor(self, sensor_name: str, cipher_type: str):
        """Add a sensor with specific cipher"""
        sender = IoTSender(
            device_id=f"{self.device_id}_{sensor_name}",
            cipher_type=cipher_type,
            server_host=self.server_host,
            server_port=self.server_port,
            on_disconnect=self._on_sensor_disconnect
        )
        self.senders[sensor_name] = sender

    def _on_sensor_disconnect(self, device_id: str):
        """Handle sensor disconnection"""
        print(f"[DEVICE] Sensor {device_id} disconnected")

    def connect_all(self) -> bool:
        """Connect all sensors to server"""
        success = True
        for name, sender in self.senders.items():
            print(f"Connecting {name} sensor...")
            if not sender.connect():
                print(f"Failed to connect {name}")
                success = False
            time.sleep(0.5)
        return success

    def disconnect_all(self):
        """Disconnect all sensors"""
        for sender in self.senders.values():
            sender.disconnect()

    def run_sequential_simulation(self, durations: Optional[Dict] = None):
        """Run sensors one after another"""
        if durations is None:
            durations = {
                "temperature": 15,
                "heart_rate": 15,
                "blood_pressure": 15
            }

        print(f"\n{'=' * 60}")
        print(f"Starting IoT Device: {self.device_id} - SEQUENTIAL MODE")
        print(f"{'=' * 60}")

        if not self.connect_all():
            print("Failed to connect sensors. Exiting.")
            self.disconnect_all()
            return

        try:
            for sensor_name, duration in durations.items():
                if sensor_name in self.senders:
                    print(f"\n{'-' * 40}")
                    print(f"Simulating {sensor_name}")
                    print(f"{'-' * 40}")

                    sender = self.senders[sensor_name]
                    if not sender.connected:
                        print(f"Reconnecting {sensor_name}...")
                        sender.connect()

                    sender.simulate_sensor_stream(
                        sensor_type=sensor_name,
                        duration_seconds=duration
                    )

                    print("Pausing before next sensor...")
                    time.sleep(2)

        except KeyboardInterrupt:
            print("\nSimulation interrupted by user")
        finally:
            self.disconnect_all()
            self.print_statistics()

    def run_parallel_simulation(self, duration: int = 20):
        """Run all sensors simultaneously"""
        print(f"\n{'=' * 60}")
        print(f"Starting IoT Device: {self.device_id} - PARALLEL MODE")
        print(f"{'=' * 60}")

        if not self.connect_all():
            print("Failed to connect sensors. Exiting.")
            self.disconnect_all()
            return

        threads = []

        def run_sensor(sensor_name):
            sender = self.senders[sensor_name]
            print(f"\nStarting {sensor_name}")
            sender.simulate_sensor_stream(
                sensor_type=sensor_name,
                duration_seconds=duration
            )

        for sensor_name in self.senders.keys():
            thread = threading.Thread(
                target=run_sensor,
                args=(sensor_name,),
                daemon=True
            )
            thread.start()
            threads.append(thread)
            time.sleep(0.5)

        for thread in threads:
            thread.join()

        self.disconnect_all()
        self.print_statistics()

    def print_statistics(self):
        """Print device statistics"""
        print("\n" + "=" * 60)
        print("DEVICE STATISTICS")
        print("=" * 60)

        total_packets = 0
        total_bytes = 0

        for name, sender in self.senders.items():
            stats = sender.get_statistics()
            packets = stats.get("packets_sent", 0)
            bytes_sent = stats.get("bytes_sent", 0)
            reconnects = stats.get("reconnects", 0)

            total_packets += packets
            total_bytes += bytes_sent

            print(f"\n{name.upper()} ({sender.cipher_type}):")
            print(f"  Packets: {packets}")
            print(f"  Bytes: {bytes_sent}")
            print(f"  Reconnects: {reconnects}")

        print("\nTOTAL:")
        print(f"  Packets: {total_packets}")
        print(f"  Bytes: {total_bytes}")
        print(f"  MB: {total_bytes / (1024 * 1024):.2f}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="IoT Device Sender")
    parser.add_argument('--mode', choices=['sequential', 'parallel'], default='parallel',
                        help='Simulation mode')
    parser.add_argument('--duration', type=int, default=20,
                        help='Duration in seconds')
    args = parser.parse_args()

    iot_device = SecureIoTDevice("PATIENT_001", "localhost", 9999)

    iot_device.add_sensor("temperature", "PRESENT")
    iot_device.add_sensor("heart_rate", "SIMON")
    iot_device.add_sensor("blood_pressure", "SPECK")

    print("\nIoT Device initialized. Starting communication...")
    print("Make sure receiver.py is running first!")
    time.sleep(2)

    if args.mode == 'sequential':
        iot_device.run_sequential_simulation()
    else:
        iot_device.run_parallel_simulation(duration=args.duration)