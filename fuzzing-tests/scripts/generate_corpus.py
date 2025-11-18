#!/usr/bin/env python3
"""Generate binary corpus files for FGCom fuzzing"""
import struct
import os
import math
import random

def create_corpus():
    os.makedirs('corpus', exist_ok=True)
    
    # Radio Propagation Seeds
    with open('corpus/radio_valid.bin', 'wb') as f:
        f.write(struct.pack('f', 118.5))      # Frequency
        f.write(struct.pack('d', 37.7749))    # Latitude
        f.write(struct.pack('d', -122.4194))  # Longitude
        f.write(struct.pack('d', 37.7849))    # Latitude 2
        f.write(struct.pack('d', -122.4094))  # Longitude 2
        f.write(struct.pack('f', 100.0))      # Power
        f.write(struct.pack('f', 10.0))       # Antenna gain
        f.write(struct.pack('f', -80.0))      # Noise floor
        f.write(struct.pack('?', True))       # Line of sight
    
    with open('corpus/radio_edge.bin', 'wb') as f:
        f.write(struct.pack('f', 137.0))      # Max frequency
        f.write(struct.pack('d', 90.0))       # Max latitude
        f.write(struct.pack('d', 180.0))      # Max longitude
        f.write(struct.pack('d', -90.0))      # Min latitude
        f.write(struct.pack('d', -180.0))     # Min longitude
        f.write(struct.pack('f', 1000.0))     # Max power
        f.write(struct.pack('f', 20.0))       # Max antenna gain
        f.write(struct.pack('f', -60.0))     # Max noise floor
        f.write(struct.pack('?', False))     # No line of sight
    
    # Audio Processing Seeds
    with open('corpus/audio_silence.bin', 'wb') as f:
        f.write(struct.pack('i', 22050))      # Sample rate
        f.write(struct.pack('I', 2205))      # Audio size (100ms)
        f.write(struct.pack('f', -60.0))     # Squelch threshold
        f.write(struct.pack('f', 1.0))       # AGC gain
        f.write(struct.pack('f', 10.0))      # AGC attack
        f.write(struct.pack('f', 100.0))     # AGC release
        # 100ms of silence at 22050 Hz, 16-bit
        for _ in range(2205):
            f.write(struct.pack('h', 0))
    
    with open('corpus/audio_tone.bin', 'wb') as f:
        f.write(struct.pack('i', 44100))      # Sample rate
        f.write(struct.pack('I', 4410))      # Audio size (100ms)
        f.write(struct.pack('f', -40.0))     # Squelch threshold
        f.write(struct.pack('f', 2.0))       # AGC gain
        f.write(struct.pack('f', 5.0))       # AGC attack
        f.write(struct.pack('f', 50.0))      # AGC release
        # 100ms 1kHz tone
        for i in range(4410):
            sample = int(32767 * 0.5 * math.sin(2 * math.pi * 1000 * i / 44100))
            f.write(struct.pack('h', sample))
    
    with open('corpus/audio_noise.bin', 'wb') as f:
        f.write(struct.pack('i', 48000))      # Sample rate
        f.write(struct.pack('I', 4800))      # Audio size (100ms)
        f.write(struct.pack('f', -80.0))     # Squelch threshold
        f.write(struct.pack('f', 0.5))       # AGC gain
        f.write(struct.pack('f', 20.0))      # AGC attack
        f.write(struct.pack('f', 200.0))     # AGC release
        # 100ms of noise
        for _ in range(4800):
            sample = int(32767 * 0.1 * (random.random() - 0.5))
            f.write(struct.pack('h', sample))
    
    # Network Protocol Seeds
    with open('corpus/udp_minimal.bin', 'wb') as f:
        f.write(b'\x00\x00\x00\x01')  # Protocol type (UDP)
        f.write(struct.pack('H', 1234))  # Port
        f.write(b'127.0.0.1')  # Host
        f.write(b'\x00\x01\x02\x03')  # IP address
        f.write(b'FGCOM')  # Magic
    
    with open('corpus/http_request.bin', 'wb') as f:
        f.write(b'\x00\x00\x00\x01')  # Protocol type (HTTP)
        f.write(struct.pack('H', 8080))  # Port
        f.write(b'localhost')  # Host
        f.write(b'\x7f\x00\x00\x01')  # IP address
        http = b'GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n'
        f.write(http)
    
    with open('corpus/mumble_packet.bin', 'wb') as f:
        f.write(b'\x00\x00\x00\x02')  # Protocol type (MUMBLE)
        f.write(struct.pack('H', 64738))  # Port
        f.write(b'mumble.example.com')  # Host
        f.write(b'\xc0\xa8\x01\x01')  # IP address
        # Mumble packet
        f.write(struct.pack('H', 0))  # Type (Version)
        f.write(struct.pack('I', 8))  # Length
        f.write(b'1.2.3')  # Version string
    
    # Security Functions Seeds
    with open('corpus/crypto_aes.bin', 'wb') as f:
        f.write(b'\x00')  # Algorithm (AES)
        f.write(b'\x20')  # Key size (32 bytes)
        f.write(os.urandom(32))  # 256-bit key
        f.write(os.urandom(16))  # 128-bit IV
        f.write(b'plaintext message')  # Message
    
    with open('corpus/crypto_hash.bin', 'wb') as f:
        f.write(b'\x01')  # Algorithm (HASH)
        f.write(b'\x10')  # Key size (16 bytes)
        f.write(os.urandom(16))  # 128-bit key
        f.write(os.urandom(16))  # 128-bit IV
        f.write(b'data to hash')  # Message
    
    with open('corpus/crypto_auth.bin', 'wb') as f:
        f.write(b'\x02')  # Algorithm (AUTH)
        f.write(b'\x18')  # Key size (24 bytes)
        f.write(os.urandom(24))  # 192-bit key
        f.write(os.urandom(16))  # 128-bit IV
        f.write(b'username:password')  # Credentials
    
    # Data Parsing Seeds
    with open('corpus/json_valid.bin', 'wb') as f:
        f.write(b'\x00')  # Parse type (JSON)
        json_data = b'{"frequency":118.5,"callsign":"N12345","altitude":5000}'
        f.write(json_data)
    
    with open('corpus/json_minimal.bin', 'wb') as f:
        f.write(b'\x00')  # Parse type (JSON)
        f.write(b'{}')
    
    with open('corpus/json_nested.bin', 'wb') as f:
        f.write(b'\x00')  # Parse type (JSON)
        json_data = b'{"radio":{"freq":118.5,"mode":"AM"},"aircraft":{"callsign":"N12345"}}'
        f.write(json_data)
    
    with open('corpus/xml_valid.bin', 'wb') as f:
        f.write(b'\x01')  # Parse type (XML)
        xml_data = b'<?xml version="1.0"?><radio><frequency>118.5</frequency></radio>'
        f.write(xml_data)
    
    with open('corpus/sql_select.bin', 'wb') as f:
        f.write(b'\x02')  # Parse type (SQL)
        sql_data = b'SELECT * FROM aircraft WHERE frequency = 118.5'
        f.write(sql_data)
    
    with open('corpus/config_valid.bin', 'wb') as f:
        f.write(b'\x03')  # Parse type (CONFIG)
        config_data = b'frequency=118.5\ncallsign=N12345\naltitude=5000'
        f.write(config_data)
    
    with open('corpus/atis_valid.bin', 'wb') as f:
        f.write(b'\x04')  # Parse type (ATIS)
        atis_data = b'ATIS KORD WIND 270/15 VISIBILITY 10 TEMP 20 PRESSURE 2992'
        f.write(atis_data)
    
    # Mathematical Calculations Seeds
    with open('corpus/math_coords.bin', 'wb') as f:
        f.write(struct.pack('d', 37.7749))    # Latitude 1
        f.write(struct.pack('d', -122.4194)) # Longitude 1
        f.write(struct.pack('d', 37.7849))    # Latitude 2
        f.write(struct.pack('d', -122.4094))  # Longitude 2
        f.write(struct.pack('d', 123.45))     # Frequency MHz
        f.write(struct.pack('d', 1000.0))     # Elevation
        f.write(struct.pack('d', 100.0))      # Power
    
    with open('corpus/math_edge.bin', 'wb') as f:
        f.write(struct.pack('d', 90.0))       # Max latitude
        f.write(struct.pack('d', 180.0))      # Max longitude
        f.write(struct.pack('d', -90.0))      # Min latitude
        f.write(struct.pack('d', -180.0))     # Min longitude
        f.write(struct.pack('d', 30000.0))   # Max frequency
        f.write(struct.pack('d', 9000.0))    # Max elevation
        f.write(struct.pack('d', 10000.0))   # Max power
    
    # File I/O Seeds
    with open('corpus/file_valid.bin', 'wb') as f:
        f.write(b'\x00')  # Operation type (FILE_PATH)
        f.write(b'/tmp/fgcom_config.txt')  # File path
        f.write(b'frequency=118.5\ncallsign=N12345')  # File content
    
    with open('corpus/file_json.bin', 'wb') as f:
        f.write(b'\x01')  # Operation type (FILE_CONTENT)
        f.write(b'config.json')  # File path
        f.write(b'{"frequency":118.5,"callsign":"N12345"}')  # File content
    
    with open('corpus/file_xml.bin', 'wb') as f:
        f.write(b'\x01')  # Operation type (FILE_CONTENT)
        f.write(b'config.xml')  # File path
        f.write(b'<?xml version="1.0"?><config><frequency>118.5</frequency></config>')  # File content
    
    # Edge cases
    with open('corpus/empty.bin', 'wb') as f:
        pass  # 0 bytes
    
    with open('corpus/single_byte.bin', 'wb') as f:
        f.write(b'\x00')
    
    with open('corpus/max_values.bin', 'wb') as f:
        f.write(b'\xFF' * 64)
    
    # Random seeds of various sizes
    for size in [8, 16, 32, 64, 128, 256, 512, 1024]:
        with open(f'corpus/random_{size}.bin', 'wb') as f:
            f.write(os.urandom(size))
    
    print(f"Created {len(os.listdir('corpus'))} corpus files")

if __name__ == '__main__':
    create_corpus()
