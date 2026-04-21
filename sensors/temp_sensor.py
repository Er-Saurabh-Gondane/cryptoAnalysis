import random
import time
import numpy as np
from typing import Dict,List,Optional
from datetime import datetime
from config import SENSOR_CONFIG


class TemperatureSensor:
    def __init__(self,device_id:str,location:str="unknown"):
        self.device_id = device_id
        self.location = location
        self.config = SENSOR_CONFIG['temperature']
        self.current_temp = 36.6 # Normal Human Temperature
        self.data_buffer = []
        self.is_running = False

    def read_sensor(self) -> Dict:
        """
            Simulate reading temperature from sensor
            Returns temperature data with metadata

        """
        # Simulate slight variations in readings
        variation = np.random.normal(0,0.1) # Normal distribution with 0.1 C std 
        self.current_temp += variation
        
        # Ensure within realistic bounds 
        self.current_temp = max(self.config['min_value'],
                                min(self.config['max_value'],
                                    self.current_temp))
        
        # Check if within normal range
        is_normal = (self.config['normal_range'][0] <= self.current_temp <= self.config['normal_range'][1])

        data = {
            'device_id':self.device_id,
            'location':self.location,
            'timestamp':datetime.now().isoformat(),
            'temprature':round(self.current_temp,2),
            'unit':self.config['unit'],
            'is_normal':is_normal,
            'battary_level':random.randint(75,100)
        }

        self.data_buffer.append(data)

        return data
    

    def simulate_fever(self, duration_seconds:int = 30):
        """ Simulate a fever condition for testing """
        print(f"Simulating fever on device {self.device_id} for {duration_seconds}s")
        start_time = time.time()

        while time.time() - start_time < duration_seconds:
            self.current_temp += np.random.uniform(0.1 ,0.3)
            if self.current_temp > 39.5:
                self.current_temp = 39.5
            
            time.sleep(1)
            yield self.read_sensor() # read temperature from device and return metadata

    

    def get_statistics(self) -> Dict:
        """ Get Statistical summary of collected data """
        if not self.data_buffer:
            return {}
        
        temps = [d['temperature'] for d in self.data_buffer]
        return {
            'mean': np.mean(temps),
            'median': np.median(temps),
            'std': np.std(temps),
            'min': min(temps),
            'max': max(temps),
            'readings_count': len(temps),
            'abnormal_readings': sum(1 for d in self.data_buffer if not d['is_normal'])
        }
    
    def reset(self):
        """ Reset sensor to initial state """
        self.current_temp = 36.6
        self.data_buffer = []

# test the sensor
if __name__ == '__main__':
    sensor = TemperatureSensor("TEMP_001","patient_room_1")

    print("Testing temperature sensor...")
    for _ in range(10):
        data  = sensor.read_sensor()
        print(f"Temperature: {data['temperature']}{data['unit']} - "
              f"{'Normal' if data['is_normal'] else 'Abnormal'}")
        time.sleep(0.5)
    
    print("\nSensor Statistics:")
    stats = sensor.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")