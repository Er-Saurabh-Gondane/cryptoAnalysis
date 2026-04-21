"""
Heart Rate Sensor for simulation iot devices 
"""
import random
import time
import numpy as np
from typing import Dict, Generator,Optional
from datetime import datetime
from enum import Enum
from config import SENSOR_CONFIG

class ActivityLevel(Enum):
    RESTING = "resting"
    LIGHT_ACTIVITY = "light_activity"
    MODERATE_ACTIVITY = "moderate_activity"
    INTENSE_ACTIVITY = "intense_activity"

class HeartRateSensor:
    def __init__(self,device_id:str,patient_age:int = 30):
        self.device_id = device_id
        self.patient_age = patient_age
        self.config = SENSOR_CONFIG['heart_rate']
        self.current_hr = 70 # Resting heart Rate
        self.activity_level = ActivityLevel.RESTING
        self.data_buffer = []
        self.arrhythmia_mode = False
        
    
    def calculate_max_hr(self) -> int :
        # Calculate heart rate based on age
        return 220 - self.patient_age
    
    def set_activity_level(self,level: ActivityLevel):
        # Set patient activity level
        self.activity_level = level

        # Adjust heart rate based on activity
        activity_multipliers = {
            ActivityLevel.RESTING: 1.0,
            ActivityLevel.LIGHT_ACTIVITY: 1.3,
            ActivityLevel.MODERATE_ACTIVITY: 1.6,
            ActivityLevel.INTENSE_ACTIVITY: 2.0
        }
        base_hr = 70 # Resting HR
        self.current_hr = base_hr * activity_multipliers[level]
        self.current_hr = min(self.current_hr,self.calculate_max_hr())


    def enable_arrhythmia_simulation(self, enable: bool = True):
        """Enable simulation of irregular heartbeat"""
        self.arrhythmia_mode = enable
    
    def read_sensor(self) -> Dict:
        # Simulation reading heart rate from sensor
        max_hr = self.calculate_max_hr()

        # Simulation natural variation 
        if self.arrhythmia_mode:
            # Simulation arrhythmia with irregular patterns
            variation  = np.random.choice([
                np.random.normal(0,5), # Normal variation
                np.random.normal(-20,10), # Sudden drop
                np.random.normal(30,15), # Sudden spike
            ],p = [0.7,0.15,0.15])
        else:
            variation = np.random.normal(0,2)
        
        self.current_hr += variation

        # Ensure within bounds
        self.current_hr = max(self.config['min_value'],
                              min(self.config['max_value'],self.current_hr))
        
        # Check if withing normal range
        normal_min , normal_max = self.config['normal_range']
        is_normal = (normal_min <= self.current_hr <= normal_max)

        # Calculate HRV (Heart Rate Variability ) - simplified

        hrv = np.random.uniform(20,60) if is_normal else np.random.uniform(5,20)

        data = {
            'device_id': self.device_id,
            'timestamp': datetime.now().isoformat(),
            'heart_rate': int(self.current_hr),
            'unit': self.config['unit'],
            'activity_level': self.activity_level.value,
            'is_normal': is_normal,
            'hrv_ms': round(hrv, 1),
            'max_heart_rate': max_hr,
            'arrhythmia_detected': self.arrhythmia_mode and variation < -15,
            'battery_level': random.randint(70, 100)
        } 

        self.data_buffer.append(data)
        return data
    
    def simulate_exercise_session(self,duration_minutes:int = 5) -> Generator:
        """Simulate heart rate during exercise"""
        print(f"Starting exercise session on {self.device_id} for {duration_minutes} minutes")

        stages = [
            (0, 0.2, ActivityLevel.RESTING),        # Warm-up start
            (0.2, 0.4, ActivityLevel.LIGHT_ACTIVITY),  # Light activity
            (0.4, 0.7, ActivityLevel.MODERATE_ACTIVITY),  # Moderate exercise
            (0.7, 0.9, ActivityLevel.INTENSE_ACTIVITY),   # Peak exercise
            (0.9, 1.0, ActivityLevel.LIGHT_ACTIVITY),     # Cool down
        ]
        
        start_time = time.time()
        total_seconds = duration_minutes * 60

        while True:
            elapsed = time.time() - start_time
            progress = elapsed / total_seconds

            if progress > 1.0:
                break

            # Determine activity level based on progress
            for stage_start, stage_end, level in stages:
             if stage_start <= progress < stage_end:
                self.set_activity_level(level)
                break
            
            yield self.read_sensor()
            time.sleep(1) # Read every second
    
    def get_statistics(self) -> Dict:
        if not self.data_buffer:
            return {}
        
        hrs = [d['heart_rate'] for d in self.data_buffer]
        hrv_values = [d['hrv_ms'] for d in self.data_buffer if d['hrv_ms']]

        return {
            'mean_hr': np.mean(hrs),
            'min_hr': min(hrs),
            'max_hr': max(hrs),
            'hr_variability': np.std(hrs),
            'mean_hrv': np.mean(hrv_values) if hrv_values else 0,
            'readings_count': len(hrs),
            'abnormal_readings': sum(1 for d in self.data_buffer if not d['is_normal']),
            'arrhythmia_events': sum(1 for d in self.data_buffer if d.get('arrhythmia_detected'))
        }
    

if __name__ == '__main__':
    sensor = HeartRateSensor("HR_001",patient_age = 35) 
    print("Testing heart rate sensor at rest...")
    for _ in range(10):
      data = sensor.read_sensor()
      print(f"Heart Rate: {data['heart_rate']}{data['unit']} - "
            f"{'Normal' if data['is_normal'] else 'Abnormal'} (HRV: {data['hrv_ms']}ms)")
      time.sleep(0.5)
    
    print("\nSimulating exercise session...")
    for i, data in enumerate(sensor.simulate_exercise_session(duration_minutes=1)):
        if i % 10 == 0:  # Print every 10th reading
            print(f"  {data['activity_level']}: {data['heart_rate']} bpm")
    
    print("\nSensor Statistics:")
    stats = sensor.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value:.1f}" if isinstance(value, float) else f"  {key}: {value}")
