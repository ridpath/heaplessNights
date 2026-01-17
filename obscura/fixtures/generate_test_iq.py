"""
Generate test .iq files for SDR attack testing
Creates sample GPS, ADS-B, and generic RF waveforms for dry-run testing
"""

import struct
import random
import math
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent
SAMPLE_RATE = 2600000
DURATION = 10


def generate_gps_l1_sample():
    """Generate sample GPS L1 C/A signal."""
    output = FIXTURES_DIR / 'gps_l1_sample.bin'
    
    samples = SAMPLE_RATE * DURATION
    amplitude = 30000
    
    with open(output, 'wb') as f:
        for i in range(samples):
            noise_i = random.randint(-5000, 5000)
            noise_q = random.randint(-5000, 5000)
            
            signal_i = int(amplitude * 0.3 * math.sin(2 * math.pi * i * 1023000 / SAMPLE_RATE))
            signal_q = int(amplitude * 0.3 * math.cos(2 * math.pi * i * 1023000 / SAMPLE_RATE))
            
            i_sample = signal_i + noise_i
            q_sample = signal_q + noise_q
            
            i_sample = max(-32768, min(32767, i_sample))
            q_sample = max(-32768, min(32767, q_sample))
            
            f.write(struct.pack('<hh', i_sample, q_sample))
    
    print(f"Generated: {output} ({samples} samples, {DURATION}s)")


def generate_adsb_sample():
    """Generate sample ADS-B Mode-S signal."""
    output = FIXTURES_DIR / 'adsb_sample.bin'
    
    samples = SAMPLE_RATE * DURATION
    amplitude = 30000
    
    with open(output, 'wb') as f:
        for i in range(samples):
            if i % 10000 < 500:
                burst_i = int(amplitude * math.sin(2 * math.pi * i / 100))
                burst_q = int(amplitude * math.cos(2 * math.pi * i / 100))
            else:
                burst_i = random.randint(-1000, 1000)
                burst_q = random.randint(-1000, 1000)
            
            f.write(struct.pack('<hh', burst_i, burst_q))
    
    print(f"Generated: {output} ({samples} samples, {DURATION}s)")


def generate_315mhz_sample():
    """Generate sample 315 MHz garage door opener signal."""
    output = FIXTURES_DIR / '315mhz_garage.bin'
    
    samples = SAMPLE_RATE * 2
    amplitude = 30000
    
    with open(output, 'wb') as f:
        for i in range(samples):
            if i % 1000 < 100:
                signal_i = amplitude
                signal_q = 0
            else:
                signal_i = 0
                signal_q = 0
            
            noise_i = random.randint(-500, 500)
            noise_q = random.randint(-500, 500)
            
            f.write(struct.pack('<hh', signal_i + noise_i, signal_q + noise_q))
    
    print(f"Generated: {output} ({samples} samples, 2s)")


def generate_433mhz_sample():
    """Generate sample 433 MHz alarm system signal."""
    output = FIXTURES_DIR / '433mhz_alarm.bin'
    
    samples = SAMPLE_RATE * 2
    amplitude = 30000
    
    pattern = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0]
    
    with open(output, 'wb') as f:
        for i in range(samples):
            bit_index = (i // 500) % len(pattern)
            
            if pattern[bit_index]:
                signal_i = int(amplitude * math.sin(2 * math.pi * i / 50))
                signal_q = int(amplitude * math.cos(2 * math.pi * i / 50))
            else:
                signal_i = random.randint(-1000, 1000)
                signal_q = random.randint(-1000, 1000)
            
            f.write(struct.pack('<hh', signal_i, signal_q))
    
    print(f"Generated: {output} ({samples} samples, 2s)")


def generate_noise_sample():
    """Generate white noise sample for jamming tests."""
    output = FIXTURES_DIR / 'noise_jamming.bin'
    
    samples = SAMPLE_RATE * 5
    
    with open(output, 'wb') as f:
        for _ in range(samples):
            i_sample = random.randint(-32768, 32767)
            q_sample = random.randint(-32768, 32767)
            f.write(struct.pack('<hh', i_sample, q_sample))
    
    print(f"Generated: {output} ({samples} samples, 5s)")


if __name__ == '__main__':
    print("Generating test .iq fixture files...")
    print(f"Output directory: {FIXTURES_DIR}")
    print(f"Sample rate: {SAMPLE_RATE} Hz")
    print()
    
    generate_gps_l1_sample()
    generate_adsb_sample()
    generate_315mhz_sample()
    generate_433mhz_sample()
    generate_noise_sample()
    
    print()
    print("All fixtures generated successfully!")
