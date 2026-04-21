"""
Receiver module for IoT data
Receives and decrypts sensor data from IoT devices
"""

import socket
import json
import threading
import time
from typing import Dict, Any
from datetime import datetime
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


class IoTReceiver:
    """Receiver server for IoT device data"""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.server_socket = None
        self.clients = {}
        self.ciphers = {}
        self.received_data = []
        self.running = False
        self.lock = threading.Lock()
        self.secure_channel = SecureChannel()
        self.client_threads = []

        # Setup signal handlers safely
        try:
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
        except Exception:
            pass

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        print(f"\n[SERVER] Received signal {signum}. Shutting down...")
        self.stop()

    def _create_cipher(self, cipher_type: str, key_size: int = 128):
        cipher_type = cipher_type.upper()

        if cipher_type == "PRESENT":
            return PresentCipher(key_size)
        elif cipher_type == "SIMON":
            return SimonCipher("64/128")
        elif cipher_type == "SPECK":
            return SpeckCipher("64/128")
        elif cipher_type == "GIFT":
            return GiftCipher()
        elif cipher_type == "TINYJAMBU":
            return TinyJambuCipher(128, "128")
        else:
            raise ValueError(f"Unsupported cipher: {cipher_type}")

    def start(self):
        """Start the receiver server"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1.0)

            self.running = True
            print(f"[SERVER] Listening on {self.host}:{self.port}")
            print("[SERVER] Secure Channel: Enabled")
            print("[SERVER] Press Ctrl+C to stop")

            cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
            cleanup_thread.start()

            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"[SERVER] New connection from {address}")

                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()

                    with self.lock:
                        self.client_threads.append(client_thread)

                except socket.timeout:
                    continue
                except OSError:
                    # Happens when socket is closed during shutdown
                    break
                except Exception as e:
                    if self.running:
                        print(f"[SERVER] Error accepting connection: {e}")

        except Exception as e:
            print(f"[SERVER] Failed to start: {e}")
        finally:
            self.stop()

    def stop(self):
        """Stop the receiver server"""
        if not self.running:
            return

        print("[SERVER] Shutting down...")
        self.running = False

        with self.lock:
            for client_info in self.clients.values():
                try:
                    client_info["socket"].close()
                except Exception:
                    pass
                try:
                    client_info["file"].close()
                except Exception:
                    pass

            self.clients.clear()
            self.ciphers.clear()

        try:
            if self.server_socket:
                self.server_socket.close()
        except Exception:
            pass

        for thread in self.client_threads:
            thread.join(timeout=2.0)

        print("[SERVER] Stopped")
        self.print_statistics()

    def _cleanup_worker(self):
        """Background thread to clean up old data"""
        while self.running:
            time.sleep(60)
            try:
                self.secure_channel.clear_old_packets()

                with self.lock:
                    if len(self.received_data) > 1000:
                        self.received_data = self.received_data[-1000:]
            except Exception as e:
                if self.running:
                    print(f"[SERVER] Cleanup error: {e}")

    def handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connection"""
        client_id = f"{address[0]}:{address[1]}"
        device_id = "unknown"
        packet_count = 0
        client_file = None

        try:
            client_socket.settimeout(30.0)
            client_file = client_socket.makefile("r", encoding="utf-8")

            handshake_line = client_file.readline()
            if not handshake_line:
                print(f"[{client_id}] Empty handshake received")
                return

            handshake = json.loads(handshake_line.strip())

            device_id = handshake.get("device_id", client_id)
            cipher_type = handshake.get("cipher_type", "SPECK").upper()
            key_size = int(handshake.get("key_size", 128))

            if not device_id:
                raise ValueError("Missing device_id in handshake")

            # Validate cipher before storing client
            cipher = self._create_cipher(cipher_type, key_size)

            print(f"[{device_id}] Connected using {cipher_type}")

            with self.lock:
                self.clients[client_id] = {
                    "socket": client_socket,
                    "file": client_file,
                    "device_id": device_id,
                    "cipher_type": cipher_type,
                    "address": address,
                    "connected_at": datetime.now().isoformat(),
                    "packet_count": 0
                }

            # Demo key for project use
            demo_key = 0x0123456789ABCDEF0123456789ABCDEF
            cipher.key_schedule(demo_key)

            with self.lock:
                self.ciphers[client_id] = cipher

            while self.running:
                try:
                    line = client_file.readline()
                    if not line:
                        break

                    stripped = line.strip()
                    if not stripped:
                        continue

                    packet = json.loads(stripped)
                    self.process_packet(client_id, packet)

                    with self.lock:
                        if client_id in self.clients:
                            self.clients[client_id]["packet_count"] += 1
                            packet_count = self.clients[client_id]["packet_count"]

                except json.JSONDecodeError:
                    print(f"[{device_id}] Received invalid JSON packet")
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[{device_id}] Error receiving data: {e}")
                    break

        except Exception as e:
            print(f"[{client_id}] Error: {e}")

        finally:
            with self.lock:
                if client_id in self.clients:
                    packet_count = self.clients[client_id].get("packet_count", packet_count)
                    del self.clients[client_id]

                if client_id in self.ciphers:
                    del self.ciphers[client_id]

            try:
                if client_file:
                    client_file.close()
            except Exception:
                pass

            try:
                client_socket.close()
            except Exception:
                pass

            print(f"[{device_id}] Disconnected (sent {packet_count} packets)")

    def process_packet(self, client_id: str, packet: Dict[str, Any]):
        """Process received packet with security verification"""
        device_id = packet.get("device_id", "unknown")
        sequence = packet.get("sequence", 0)

        try:
            with self.lock:
                client_info = self.clients.get(client_id)
                cipher = self.ciphers.get(client_id)

            if client_info is None or cipher is None:
                print(f"[{device_id}] Client session not found")
                return

            expected_cipher_type = client_info["cipher_type"]
            packet_cipher_type = packet.get("cipher", expected_cipher_type).upper()

            if packet_cipher_type != expected_cipher_type:
                print(
                    f"[{device_id}] Cipher mismatch: handshake={expected_cipher_type}, "
                    f"packet={packet_cipher_type}"
                )
                return

            is_valid, message, metadata = self.secure_channel.verify_packet(packet)

            if not is_valid:
                print(f"[{device_id}] Security check failed: {message}")
                return

            encrypted_data = bytes.fromhex(packet["data"])

            try:
                if expected_cipher_type == "TINYJAMBU":
                    nonce = sequence & 0xFFFFFFFFFFFFFFFFFFFFFFFF
                    decrypted = cipher.decrypt(encrypted_data, nonce)
                else:
                    decrypted = cipher.decrypt(encrypted_data)

                original_packet = json.loads(decrypted.decode("utf-8"))

            except Exception as e:
                print(f"[{device_id}] Decryption failed: {e}")
                return

            record = {
                "received_at": datetime.now().isoformat(),
                "device_id": device_id,
                "sequence": sequence,
                "cipher": expected_cipher_type,
                "packet_age": metadata.get("age", 0),
                "data": original_packet.get("data", {}),
                "timestamp": original_packet.get("timestamp", 0)
            }

            with self.lock:
                self.received_data.append(record)

            sensor_data = original_packet.get("data", {})
            original_timestamp = original_packet.get("timestamp", 0)

            try:
                readable_time = datetime.fromtimestamp(original_timestamp).strftime('%H:%M:%S')
            except Exception:
                readable_time = "invalid"

            print(f"\n[RECEIVED] {datetime.now().strftime('%H:%M:%S')}")
            print(f"  Device: {device_id} (Seq: {sequence})")
            print(f"  Cipher: {expected_cipher_type}")
            print(f"  Age: {metadata.get('age', 0)}s")
            print(f"  Original Time: {readable_time}")

            if "temperature" in sensor_data:
                temp = sensor_data["temperature"]
                status = "OK" if sensor_data.get("is_normal", True) else "ALERT"
                print(f"  {status} Temperature: {temp}°C")

            elif "heart_rate" in sensor_data:
                hr = sensor_data["heart_rate"]
                hrv = sensor_data.get("hrv_ms", "N/A")
                print(f"  Heart Rate: {hr} bpm")
                print(f"  HRV: {hrv} ms")
                if sensor_data.get("arrhythmia_detected"):
                    print("  ALERT: ARRHYTHMIA DETECTED")

            elif "systolic" in sensor_data:
                systolic = sensor_data["systolic"]
                diastolic = sensor_data.get("diastolic", "N/A")
                category = sensor_data.get("category", "unknown")
                print(f"  BP: {systolic}/{diastolic} mmHg")
                print(f"  Category: {category}")

            else:
                print(f"  Data: {sensor_data}")

        except Exception as e:
            print(f"[{device_id}] Failed to process packet: {e}")

    def get_statistics(self) -> Dict[str, Any]:
        """Get receiver statistics"""
        with self.lock:
            cipher_counts = {}
            for record in self.received_data:
                cipher = record["cipher"]
                cipher_counts[cipher] = cipher_counts.get(cipher, 0) + 1

            device_counts = {}
            for record in self.received_data:
                device = record["device_id"]
                device_counts[device] = device_counts.get(device, 0) + 1

            stats = {
                "total_packets": len(self.received_data),
                "active_connections": len(self.clients),
                "total_connections_ever": len(self.client_threads),
                "cipher_usage": cipher_counts,
                "device_usage": device_counts,
                "secure_channel_stats": self.secure_channel.get_statistics()
            }

        return stats

    def print_statistics(self):
        """Print receiver statistics"""
        stats = self.get_statistics()

        print("\n" + "=" * 60)
        print("RECEIVER STATISTICS")
        print("=" * 60)
        print(f"Total Packets Received: {stats['total_packets']}")
        print(f"Active Connections: {stats['active_connections']}")
        print(f"Total Connections: {stats['total_connections_ever']}")

        print("\nCipher Usage:")
        for cipher, count in stats["cipher_usage"].items():
            percentage = (count / stats["total_packets"] * 100) if stats["total_packets"] > 0 else 0
            print(f"  {cipher}: {count} packets ({percentage:.1f}%)")

        print("\nSecure Channel Stats:")
        for key, value in stats["secure_channel_stats"].items():
            print(f"  {key}: {value}")


if __name__ == "__main__":
    receiver = IoTReceiver("localhost", 9999)

    try:
        receiver.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Keyboard interrupt received")
        receiver.stop()     