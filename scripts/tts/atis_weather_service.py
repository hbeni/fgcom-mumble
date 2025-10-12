#!/usr/bin/env python3
"""
ATIS Weather Service
Systemd service wrapper for automatic ATIS weather monitoring.

This service runs continuously in the background, monitoring weather conditions
and automatically updating ATIS recordings when significant changes are detected.
"""

import os
import sys
import signal
import logging
import time
from pathlib import Path
from datetime import datetime
import json

# Add the scripts directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from atis_weather_integration import ATISWeatherMonitor

class ATISWeatherService:
    """Service wrapper for ATIS weather monitoring"""
    
    def __init__(self, config_file: str = "atis_weather_config.json"):
        self.config_file = config_file
        self.monitor = None
        self.running = False
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging for the service"""
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_file = log_dir / f"atis_weather_service_{datetime.now().strftime('%Y%m%d')}.log"
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down...")
        self.running = False
        
        if self.monitor:
            self.monitor.stop()
    
    def start(self):
        """Start the ATIS weather service"""
        self.logger.info("Starting ATIS Weather Service...")
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        try:
            # Initialize monitor
            self.monitor = ATISWeatherMonitor(self.config_file)
            self.running = True
            
            self.logger.info("ATIS Weather Service started successfully")
            self.logger.info(f"Monitoring airports: {', '.join(self.monitor.config['airports'])}")
            self.logger.info(f"Update interval: {self.monitor.config['update_interval_minutes']} minutes")
            
            # Start monitoring
            self.monitor.monitor_airports()
            
        except Exception as e:
            self.logger.error(f"Failed to start ATIS Weather Service: {e}")
            sys.exit(1)
    
    def stop(self):
        """Stop the ATIS weather service"""
        self.logger.info("Stopping ATIS Weather Service...")
        self.running = False
        
        if self.monitor:
            self.monitor.stop()
        
        self.logger.info("ATIS Weather Service stopped")
    
    def status(self):
        """Get service status"""
        try:
            if not self.monitor:
                return "Service not initialized"
            
            status_info = {
                "running": self.running,
                "airports": self.monitor.config['airports'],
                "last_check": {},
                "weather_cache": {}
            }
            
            # Get last check times for each airport
            for airport in self.monitor.config['airports']:
                if airport in self.monitor.last_weather_check:
                    status_info["last_check"][airport] = self.monitor.last_weather_check[airport].isoformat()
                
                if airport in self.monitor.weather_cache:
                    weather = self.monitor.weather_cache[airport]
                    status_info["weather_cache"][airport] = {
                        "wind": f"{weather.wind_direction_deg:03d}@{weather.wind_speed_kts:.0f}kt",
                        "visibility": f"{weather.visibility_km:.1f}km",
                        "temperature": f"{weather.temperature_celsius:.0f}°C",
                        "pressure": f"{weather.qnh_hpa:.0f}hPa",
                        "timestamp": weather.timestamp.isoformat()
                    }
            
            return json.dumps(status_info, indent=2)
            
        except Exception as e:
            return f"Error getting status: {e}"

def main():
    """Main function for the service"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ATIS Weather Service')
    parser.add_argument('--config', default='atis_weather_config.json',
                       help='Configuration file path')
    parser.add_argument('--start', action='store_true',
                       help='Start the service')
    parser.add_argument('--stop', action='store_true',
                       help='Stop the service')
    parser.add_argument('--status', action='store_true',
                       help='Get service status')
    parser.add_argument('--daemon', action='store_true',
                       help='Run as daemon')
    
    args = parser.parse_args()
    
    service = ATISWeatherService(args.config)
    
    if args.start or args.daemon:
        service.start()
    elif args.stop:
        service.stop()
    elif args.status:
        print(service.status())
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
