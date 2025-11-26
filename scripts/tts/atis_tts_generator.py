#!/usr/bin/env python3

"""
FGcom-Mumble ATIS TTS Generator
Integrates Piper TTS with existing FGcom-Mumble ATIS system
"""

import os
import sys
import subprocess
import random
import configparser
from datetime import datetime

class ATISTTSGenerator:
    def __init__(self, config_file=None):
        """Initialize the ATIS TTS Generator"""
        self.config = configparser.ConfigParser()
        self.load_config(config_file)
        self.setup_directories()
        
    def load_config(self, config_file):
        """Load configuration from file"""
        if config_file is None:
            config_file = os.path.join(os.path.dirname(__file__), 'tts_config.conf')
        
        if os.path.exists(config_file):
            self.config.read(config_file)
        else:
            # Default configuration
            self.config['piper'] = {
                'piper_dir': '/opt/piper',
                'models_dir': '/opt/piper/models',
                'default_model': 'en_US-lessac-medium',
                'voice_speed': '1.0'
            }
            self.config['output'] = {
                'output_dir': '/tmp/fgcom-atis',
                'recordings_dir': '/home/haaken/github-projects/fgcom-mumble-dev/server/recordings',
                'audio_format': 'wav',
                'sample_rate': '48000',
                'bit_depth': '16',
                'channels': '1'
            }
            self.config['atis'] = {
                'default_template': 'standard_atis.txt',
                'templates_dir': os.path.join(os.path.dirname(__file__), 'atis_templates'),
                'letter_rotation': 'true',
                'update_interval': '30',
                'weather_source': 'simulated'
            }
    
    def setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.config.get('output', 'output_dir', fallback='/tmp/fgcom-atis'),
            self.config.get('output', 'recordings_dir', fallback='/tmp/fgcom-recordings'),
            os.path.join(self.config.get('output', 'recordings_dir', fallback='/tmp/fgcom-recordings'), 'atis')
        ]
        
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
    
    def get_piper_path(self):
        """Get the path to the Piper executable"""
        return os.path.join(
            self.config.get('piper', 'piper_dir', fallback='/opt/piper'),
            'piper'
        )
    
    def get_model_path(self, model_name=None):
        """Get the path to the Piper model"""
        if model_name is None:
            model_name = self.config.get('piper', 'default_model', fallback='en_US-lessac-medium')
        
        models_dir = self.config.get('piper', 'models_dir', fallback='/opt/piper/models')
        return os.path.join(models_dir, model_name)
    
    def check_piper_installation(self):
        """Check if Piper is properly installed"""
        piper_path = self.get_piper_path()
        if not os.path.exists(piper_path):
            print(f"ERROR: Piper not found at {piper_path}")
            return False
        
        try:
            result = subprocess.run([piper_path, '--help'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False
    
    def generate_weather_data(self):
        """Generate simulated weather data"""
        wind_directions = ['270', '280', '290', '300', '310', '320', '330', '340', '350', '360', '010', '020', '030', '040', '050', '060', '070', '080', '090', '100']
        weather_conditions = ['Clear', 'Few clouds', 'Scattered clouds', 'Broken clouds', 'Overcast', 'Light rain', 'Heavy rain', 'Thunderstorms']
        
        return {
            'wind_direction': random.choice(wind_directions),
            'wind_speed': random.randint(5, 25),
            'visibility': random.randint(5, 15),
            'weather_conditions': random.choice(weather_conditions),
            'temperature': random.randint(10, 30),
            'dew_point': random.randint(5, 25),
            'altimeter': f"{random.randint(29, 30)}.{random.randint(0, 99):02d}"
        }
    
    def get_atis_letter(self):
        """Get the current ATIS letter (A-Z)"""
        # Simple rotation based on hour
        hour = datetime.now().hour
        return chr(65 + (hour % 26))  # A-Z
    
    def load_template(self, template_name=None):
        """Load ATIS template"""
        if template_name is None:
            template_name = self.config.get('atis', 'default_template', fallback='standard_atis.txt')
        
        templates_dir = self.config.get('atis', 'templates_dir', fallback='atis_templates')
        template_path = os.path.join(templates_dir, template_name)
        
        if os.path.exists(template_path):
            with open(template_path, 'r') as f:
                return f.read().strip()
        else:
            # Default template
            return "This is {{AIRPORT_CODE}} information {{ATIS_LETTER}}. Wind {{WIND_DIRECTION}} at {{WIND_SPEED}} knots. Visibility {{VISIBILITY}} miles. {{WEATHER_CONDITIONS}}. Temperature {{TEMPERATURE}} degrees Celsius. Altimeter {{ALTIMETER}}. Advise on initial contact you have information {{ATIS_LETTER}}."
    
    def generate_atis_text(self, airport_code, template_name=None):
        """Generate ATIS text with weather data"""
        template = self.load_template(template_name)
        weather = self.generate_weather_data()
        atis_letter = self.get_atis_letter()
        
        # Replace template variables
        atis_text = template.replace('{{AIRPORT_CODE}}', airport_code)
        atis_text = atis_text.replace('{{ATIS_LETTER}}', atis_letter)
        atis_text = atis_text.replace('{{WIND_DIRECTION}}', weather['wind_direction'])
        atis_text = atis_text.replace('{{WIND_SPEED}}', str(weather['wind_speed']))
        atis_text = atis_text.replace('{{VISIBILITY}}', str(weather['visibility']))
        atis_text = atis_text.replace('{{WEATHER_CONDITIONS}}', weather['weather_conditions'])
        atis_text = atis_text.replace('{{TEMPERATURE}}', str(weather['temperature']))
        atis_text = atis_text.replace('{{DEW_POINT}}', str(weather['dew_point']))
        atis_text = atis_text.replace('{{ALTIMETER}}', weather['altimeter'])
        atis_text = atis_text.replace('{{RUNWAY}}', f"{random.randint(1, 36):02d}")
        
        return atis_text
    
    def generate_atis_audio(self, airport_code, output_file, model_name=None, template_name=None):
        """Generate ATIS audio using Piper TTS"""
        if not self.check_piper_installation():
            print("ERROR: Piper TTS not properly installed")
            return False
        
        # Generate ATIS text
        atis_text = self.generate_atis_text(airport_code, template_name)
        print(f"Generated ATIS text: {atis_text}")
        
        # Create temporary text file
        temp_text_file = f"/tmp/atis_text_{random.randint(1000, 9999)}.txt"
        try:
            with open(temp_text_file, 'w') as f:
                f.write(atis_text)
            
            # Get Piper paths
            piper_path = self.get_piper_path()
            model_path = self.get_model_path(model_name)
            voice_speed = self.config.get('piper', 'voice_speed', fallback='1.0')
            
            # Create output directory
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            # Run Piper TTS
            cmd = [
                piper_path,
                '--model', model_path,
                '--output_file', output_file,
                '--length_scale', voice_speed
            ]
            
            print(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, stdin=open(temp_text_file, 'r'), 
                                  capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                print(f"SUCCESS: ATIS audio generated: {output_file}")
                return True
            else:
                print(f"ERROR: Piper TTS failed: {result.stderr}")
                return False
                
        finally:
            # Clean up temporary file
            if os.path.exists(temp_text_file):
                os.remove(temp_text_file)
    
    def create_fgcs_file(self, audio_file, airport_code, frequency):
        """Create FGCS format file for FGcom-Mumble server"""
        fgcs_file = audio_file.replace('.wav', '.fgcs')
        
        # Create FGCS header
        header = {
            'FGCS': '',
            'VERSION': '1.0',
            'AIRPORT': airport_code,
            'FREQUENCY': frequency,
            'TIMESTAMP': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'DURATION': '30',
            'SAMPLE_RATE': self.config.get('output', 'sample_rate', fallback='48000'),
            'CHANNELS': self.config.get('output', 'channels', fallback='1'),
            'BITS_PER_SAMPLE': self.config.get('output', 'bit_depth', fallback='16'),
            'FORMAT': 'PCM',
            'POWER': '100',
            'LATITUDE': '0.0',
            'LONGITUDE': '0.0',
            'ALTITUDE': '0',
            'HEADER_END': ''
        }
        
        # Write FGCS file
        with open(fgcs_file, 'w') as f:
            for key, value in header.items():
                f.write(f"{key}:{value}\n")
        
        # Append audio data
        if os.path.exists(audio_file):
            with open(fgcs_file, 'ab') as f:
                with open(audio_file, 'rb') as audio:
                    f.write(audio.read())
        
        print(f"FGCS file created: {fgcs_file}")
        return fgcs_file
    
    def generate_airport_atis(self, airport_code, frequency='121.650', model_name=None, template_name=None):
        """Generate complete ATIS for an airport"""
        # Create output filename
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_dir = os.path.join(
            self.config.get('output', 'recordings_dir', fallback='/tmp/fgcom-recordings'),
            'atis', airport_code
        )
        os.makedirs(output_dir, exist_ok=True)
        
        audio_file = os.path.join(output_dir, f"atis_{airport_code}_{timestamp}.wav")
        
        # Generate ATIS audio
        if self.generate_atis_audio(airport_code, audio_file, model_name, template_name):
            # Create FGCS file
            fgcs_file = self.create_fgcs_file(audio_file, airport_code, frequency)
            return audio_file, fgcs_file
        else:
            return None, None

def main():
    """Main function for command line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='FGcom-Mumble ATIS TTS Generator')
    parser.add_argument('airport', help='Airport code (e.g., KJFK)')
    parser.add_argument('--frequency', default='121.650', help='ATIS frequency')
    parser.add_argument('--model', help='Piper model name')
    parser.add_argument('--template', help='ATIS template name')
    parser.add_argument('--config', help='Configuration file')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    # Initialize generator
    generator = ATISTTSGenerator(args.config)
    
    if args.output:
        # Generate specific output file
        audio_file, fgcs_file = generator.generate_airport_atis(
            args.airport, args.frequency, args.model, args.template
        )
        if audio_file:
            print(f"Generated: {audio_file}")
            if fgcs_file:
                print(f"FGCS file: {fgcs_file}")
        else:
            print("Failed to generate ATIS")
            sys.exit(1)
    else:
        # Generate standard ATIS
        audio_file, fgcs_file = generator.generate_airport_atis(
            args.airport, args.frequency, args.model, args.template
        )
        if audio_file:
            print(f"Generated: {audio_file}")
            if fgcs_file:
                print(f"FGCS file: {fgcs_file}")
        else:
            print("Failed to generate ATIS")
            sys.exit(1)

if __name__ == '__main__':
    main()
