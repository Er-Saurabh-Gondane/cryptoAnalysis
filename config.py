import os
from pathlib import Path

# Project paths

BASE_DIR = Path(__file__).parent
RESULTS_DIR = BASE_DIR / 'results'
GRAPHS_DIR = RESULTS_DIR / 'graphs'
REPORT_DIR = BASE_DIR / 'report'

# Sensor Configuration

SENSOR_CONFIG = {
    'temperature':{
        'min_value':36.0, # celcius
        'max_value': 38.5,
        'unit':"°C",
        'normal_range':(36.1,37.2)
    },
    'heart_rate':{
        'min_value':40, # BPM
        'max_value':200,
        'unit':"bpm",
        'normal_range':(60,100)
    },
    'blood_pressure':{
        'systolic_min':70, #mmHg
        'systolic_max':200,
        'diastolic_min':40,
        'diastolic_max':120,
        'unit':'mmHg',
        'normal_range':{'systolic':(90,120) ,'diastolic':(60,80)}
    }
}
# Encryption algorithm configuration
ALGORITHMS_CONFIG = {
    'PRESENT':{
        'block_size': 64,
        'key_sizes': [80, 128],
        'rounds': 31
    },
    'SIMON':{
        'block_sizes': [32, 48, 64, 96, 128],
        'key_sizes': [64, 72, 96, 128, 144, 192, 256],
        'rounds': 'variable'
    },
    'SPECK':{
        'block_sizes': [32, 48, 64, 96, 128],
        'key_sizes': [64, 72, 96, 128, 144, 192, 256],
        'rounds': 'variable'
    },
    'GIFT':{
         'block_size': 64,
        'key_sizes': [128],
        'rounds': 28
    },
    'TinyJambu':{
        'block_size': 32,
        'key_sizes': [128],
        'rounds': 384
    }
    
}

# Attacks configuration
ATTACKS_CONFIG = {
    'brute_force':{
        'max_key_attempts': 1000000,
        'timeout_seconds':300
    },
    'replay':{
        'max_replay_attempts': 100,
        'delay_between_attacks': 0.1
    },
    'mitm': {
        'max_intercepted_packets': 50
    }
}

# Benchmark configuration

BENCHMARK_CONFIG = {
    'iterations': 1000,
    'data_sizes': [16, 32, 64, 128, 256, 512, 1024],  # bytes
    'warmup_iterations': 100
}