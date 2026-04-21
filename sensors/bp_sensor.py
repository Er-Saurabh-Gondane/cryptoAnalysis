"""
Blood pressure sensor simulation for IoT devices
"""
import random
import time
import numpy as np
from typing import Dict, Tuple, Optional
from datetime import datetime
from enum import Enum
from config import SENSOR_CONFIG

class BloodPressureCategory(Enum):
    NORMAL = "normal"
    ELEVATED = "elevated"
    HYPERTENSION_STAGE_1 = "hypertension_stage_1"
    HYPERTENSION_STAGE_2 = "hypertension_stage_2"
    HYPERTENSIVE_CRISIS = "hypertensive_crisis"
    LOW = "low"

class BloodPressureSensor:
    def __init__(self, device_id: str):
        self.device_id = device_id
        self.config = SENSOR_CONFIG['blood_pressure']
        self.current_systolic = 115
        self.current_diastolic = 75
        self.data_buffer = []
        self.simulation_mode = "normal"
        
    def calculate_category(self, systolic: int, diastolic: int) -> BloodPressureCategory:
        """Determine blood pressure category based on readings"""
        if systolic < 90 or diastolic < 60:
            return BloodPressureCategory.LOW
        elif systolic < 120 and diastolic < 80:
            return BloodPressureCategory.NORMAL
        elif 120 <= systolic < 130 and diastolic < 80:
            return BloodPressureCategory.ELEVATED
        elif 130 <= systolic < 140 or 80 <= diastolic < 90:
            return BloodPressureCategory.HYPERTENSION_STAGE_1
        elif 140 <= systolic or 90 <= diastolic:
            return BloodPressureCategory.HYPERTENSION_STAGE_2
        else:
            return BloodPressureCategory.HYPERTENSIVE_CRISIS
    
    def set_simulation_mode(self, mode: str):
        """Set simulation mode: normal, hypertensive, hypotensive"""
        valid_modes = ['normal', 'hypertensive', 'hypotensive']
        if mode not in valid_modes:
            raise ValueError(f"Mode must be one of {valid_modes}")
        self.simulation_mode = mode
    
    def read_sensor(self) -> Dict:
        """Simulate reading blood pressure from sensor"""
        
        # Base values based on simulation mode
        if self.simulation_mode == 'normal':
            systolic_base, diastolic_base = 115, 75
            systolic_range, diastolic_range = (90, 130), (60, 85)
        elif self.simulation_mode == 'hypertensive':
            systolic_base, diastolic_base = 145, 95
            systolic_range, diastolic_range = (130, 180), (85, 110)
        else:  # hypotensive
            systolic_base, diastolic_base = 85, 55
            systolic_range, diastolic_range = (70, 100), (45, 65)
        
        # Simulate natural variation
        systolic_variation = np.random.normal(0, 5)
        diastolic_variation = np.random.normal(0, 3)
        
        self.current_systolic = systolic_base + systolic_variation
        self.current_diastolic = diastolic_base + diastolic_variation
        
        # Ensure within bounds
        self.current_systolic = max(systolic_range[0], 
                                   min(systolic_range[1], self.current_systolic))
        self.current_diastolic = max(diastolic_range[0], 
                                    min(diastolic_range[1], self.current_diastolic))
        
        # Round to integers
        systolic = int(round(self.current_systolic))
        diastolic = int(round(self.current_diastolic))
        
        # Calculate category
        category = self.calculate_category(systolic, diastolic)
        
        # Calculate pulse pressure and MAP (Mean Arterial Pressure)
        pulse_pressure = systolic - diastolic
        map_pressure = diastolic + (pulse_pressure // 3)
        
        data = {
            'device_id': self.device_id,
            'timestamp': datetime.now().isoformat(),
            'systolic': systolic,
            'diastolic': diastolic,
            'unit': self.config['unit'],
            'category': category.value,
            'pulse_pressure': pulse_pressure,
            'mean_arterial_pressure': map_pressure,
            'simulation_mode': self.simulation_mode,
            'battery_level': random.randint(80, 100),
            'quality_score': random.randint(85, 100)  # Signal quality
        }
        
        self.data_buffer.append(data)
        return data
    
    def simulate_measurement_series(self, count: int = 5, interval_seconds: int = 10) -> list:
        """
        Simulate a series of blood pressure measurements
        (Doctors often take multiple readings)
        """
        print(f"Taking {count} blood pressure measurements...")
        readings = []
        
        for i in range(count):
            reading = self.read_sensor()
            readings.append(reading)
            
            print(f"  Reading {i+1}: {reading['systolic']}/{reading['diastolic']} "
                  f"{reading['unit']} - {reading['category']}")
            
            if i < count - 1:
                time.sleep(interval_seconds)
        
        # Calculate average of readings
        if len(readings) > 1:
            avg_systolic = np.mean([r['systolic'] for r in readings])
            avg_diastolic = np.mean([r['diastolic'] for r in readings])
            print(f"\nAverage: {avg_systolic:.0f}/{avg_diastolic:.0f} {readings[0]['unit']}")
        
        return readings
    
    def get_statistics(self) -> Dict:
        """Get statistical summary of blood pressure data"""
        if not self.data_buffer:
            return {}
        
        systolics = [d['systolic'] for d in self.data_buffer]
        diastolics = [d['diastolic'] for d in self.data_buffer]
        
        return {
            'mean_systolic': np.mean(systolics),
            'mean_diastolic': np.mean(diastolics),
            'min_systolic': min(systolics),
            'max_systolic': max(systolics),
            'min_diastolic': min(diastolics),
            'max_diastolic': max(diastolics),
            'std_systolic': np.std(systolics),
            'std_diastolic': np.std(diastolics),
            'readings_count': len(systolics),
            'category_distribution': {
                cat: sum(1 for d in self.data_buffer if d['category'] == cat.value)
                for cat in BloodPressureCategory
            }
        }


if __name__ == "__main__":
    sensor = BloodPressureSensor("BP_001")
    
    print("Testing blood pressure sensor in normal mode...")
    for _ in range(3):
        data = sensor.read_sensor()
        print(f"BP: {data['systolic']}/{data['diastolic']} {data['unit']} - "
              f"{data['category']} (MAP: {data['mean_arterial_pressure']})")
        time.sleep(1)
    
    print("\nSwitching to hypertensive mode...")
    sensor.set_simulation_mode('hypertensive')
    sensor.simulate_measurement_series(count=3, interval_seconds=2)
    
    print("\nSensor Statistics:")
    stats = sensor.get_statistics()
    for key, value in stats.items():
        if key != 'category_distribution':
            print(f"  {key}: {value:.1f}" if isinstance(value, float) else f"  {key}: {value}")
    
    print("\nCategory Distribution:")
    for cat, count in stats['category_distribution'].items():
        if count > 0:
            print(f"  {cat}: {count}")