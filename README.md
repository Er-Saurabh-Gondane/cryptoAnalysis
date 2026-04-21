# Performance and Security Trade-off Analysis of Lightweight Cryptographic Algorithms for IoT

This repository contains the implementation and evaluation framework for the research paper titled **"Performance and Security Trade-off Analysis of Lightweight Cryptographic Algorithms for Resource-Constrained IoT Environments"** by Saurabh Y. Gondane, Prof. Ashish Soni, and Prof. Mrunalee Dhone.

## 📄 Overview

The rapid growth of IoT devices (expected to exceed 75 billion by 2025) has introduced significant security challenges. Traditional cryptographic algorithms like AES-256 are too resource-intensive for constrained devices with limited memory, low processing power, and strict battery life.

This project provides a **unified evaluation framework** that simulates an IoT environment to analyze the trade-offs between **performance** and **security** for five lightweight and ultra-lightweight cryptographic algorithms:

- PRESENT (80/128-bit)
- SIMON (64/128-bit)
- SPECK (64/128-bit)
- GIFT (64/128-bit)
- TinyJambu (128-bit)

## 🎯 Objectives

- Simulate real-world IoT sensor data (temperature, heart rate, blood pressure)
- Implement and test multiple lightweight cryptographic algorithms under identical conditions
- Evaluate performance using:
  - Encryption / Decryption time
  - Latency & Response time
  - Throughput
  - Memory usage & CPU utilization
  - Message size handling
- Simulate security attacks:
  - Replay attacks
  - Man-in-the-Middle (MITM) attacks
  - Brute force attacks
- Provide recommendations for algorithm selection based on application requirements

## 🧱 System Architecture

The system follows a modular layered design:

1. **Data Acquisition Layer** – Generates simulated IoT sensor data
2. **Cryptographic Processing Layer** – Encrypts/decrypts data using selected algorithms
3. **Performance Evaluation Layer** – Measures time, throughput, memory, CPU usage
4. **Security Analysis Layer** – Simulates replay, MITM, and brute force attacks
5. **Output & Analysis Layer** – Visualizes results and compares trade-offs

## 📊 Key Results

| Algorithm       | Speed       | Latency | Memory Usage | Throughput | Best Use Case                  |
|----------------|-------------|---------|--------------|------------|--------------------------------|
| SPECK-64/128   | Very High   | Low     | Medium       | High       | Real-time IoT applications     |
| SIMON-64/128   | High        | Low     | Medium       | Medium     | Balanced systems               |
| TinyJambu-128  | Medium      | Medium  | Very Low     | Medium     | Memory-constrained devices     |
| GIFT-64/128    | Low         | High    | Low          | Low        | Security-focused IoT           |
| PRESENT-80/128 | Low         | Very High | Medium     | Very Low   | Hardware-based low-speed systems |

### Statistical Significance

- **Throughput differences** across algorithms are statistically significant (p < 0.05)
- **Encryption time differences** are not statistically significant (p > 0.05)

## 🛡️ Security Analysis Summary

| Attack Type          | Result                                                                 |
|----------------------|------------------------------------------------------------------------|
| Replay Attack        | Successfully blocked using timestamp + sequence number validation      |
| MITM Attack          | Detected via HMAC-based integrity verification; tampered packets rejected |
| Brute Force (128-bit)| Infeasible; all algorithms resistant due to large key space            |

> TinyJambu provides additional security through **authenticated encryption**.

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Required libraries: `numpy`, `matplotlib`, `scipy`, `cryptography` (or custom lightweight crypto implementations)

### Installation

```bash
git clone https://github.com/yourusername/iot-lightweight-crypto-analysis.git
cd iot-lightweight-crypto-analysis
pip install -r requirements.txt