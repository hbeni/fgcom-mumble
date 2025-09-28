#!/usr/bin/env python3
"""
Advanced ASTER GDEM Terrain Data Downloader
Downloads ASTER Global Digital Elevation Model data for specific countries/regions
Requires NASA Earthdata account and credentials
"""

import os
import sys
import json
import requests
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse
import time

class ASTERGDEMDownloader:
    """Advanced ASTER GDEM data downloader with NASA Earthdata API integration"""
    
    def __init__(self, username: str = None, password: str = None, download_dir: str = None):
        self.username = username or os.getenv('NASA_USERNAME')
        self.password = password or os.getenv('NASA_PASSWORD')
        self.download_dir = Path(download_dir) if download_dir else Path(__file__).parent / 'terrain_data'
        self.session = requests.Session()
        
        # Setup logging
        self.setup_logging()
        
        # NASA Earthdata endpoints
        self.base_url = "https://e4ftl01.cr.usgs.gov/ASTT/ASTGTM.003/2000.02.01"
        self.api_url = "https://cmr.earthdata.nasa.gov/search/granules.json"
        
        # Country/region coordinate bounds (simplified)
        self.region_bounds = {
            'USA': {'north': 49.0, 'south': 24.0, 'east': -66.0, 'west': -125.0},
            'CAN': {'north': 84.0, 'south': 41.0, 'east': -52.0, 'west': -141.0},
            'GBR': {'north': 61.0, 'south': 49.0, 'east': 2.0, 'west': -8.0},
            'DEU': {'north': 55.0, 'south': 47.0, 'east': 15.0, 'west': 5.0},
            'FRA': {'north': 51.0, 'south': 41.0, 'east': 8.0, 'west': -5.0},
            'JPN': {'north': 46.0, 'south': 30.0, 'east': 146.0, 'west': 129.0},
            'AUS': {'north': -10.0, 'south': -44.0, 'east': 154.0, 'west': 113.0},
        }
        
        # Create directories
        self.setup_directories()
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_file = self.download_dir / 'aster_download.log'
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def setup_directories(self):
        """Create necessary directories"""
        self.download_dir.mkdir(parents=True, exist_ok=True)
        (self.download_dir / 'raw').mkdir(exist_ok=True)
        (self.download_dir / 'processed').mkdir(exist_ok=True)
        (self.download_dir / 'metadata').mkdir(exist_ok=True)
    
    def authenticate(self):
        """Authenticate with NASA Earthdata"""
        if not self.username or not self.password:
            raise ValueError("NASA Earthdata credentials required. Set NASA_USERNAME and NASA_PASSWORD environment variables or pass as arguments.")
        
        self.session.auth = (self.username, self.password)
        self.logger.info("Authenticated with NASA Earthdata")
    
    def get_available_tiles(self, region: str) -> List[Dict]:
        """Get available ASTER GDEM tiles for a region"""
        if region not in self.region_bounds:
            raise ValueError(f"Unsupported region: {region}")
        
        bounds = self.region_bounds[region]
        self.logger.info(f"Searching for ASTER GDEM tiles in region: {region}")
        
        # Query NASA CMR for available granules
        params = {
            'collection_concept_id': 'C1000000000-NASA_MAAP',  # ASTER collection
            'bounding_box': f"{bounds['west']},{bounds['south']},{bounds['east']},{bounds['north']}",
            'page_size': 2000
        }
        
        try:
            response = self.session.get(self.api_url, params=params)
            response.raise_for_status()
            data = response.json()
            
            granules = []
            for entry in data.get('feed', {}).get('entry', []):
                granule_info = {
                    'title': entry.get('title', ''),
                    'download_url': None,
                    'size': 0,
                    'bounds': entry.get('boxes', [])
                }
                
                # Find download URL
                for link in entry.get('links', []):
                    if link.get('rel') == 'http://esipfed.org/ns/fedsearch/1.1/data#':
                        granule_info['download_url'] = link.get('href')
                        break
                
                # Get file size
                for link in entry.get('links', []):
                    if link.get('rel') == 'http://esipfed.org/ns/fedsearch/1.1/data#' and 'size' in link:
                        granule_info['size'] = link.get('size', 0)
                        break
                
                if granule_info['download_url']:
                    granules.append(granule_info)
            
            self.logger.info(f"Found {len(granules)} available tiles for {region}")
            return granules
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to query NASA CMR: {e}")
            return []
    
    def download_tile(self, tile_info: Dict, region: str) -> bool:
        """Download a single ASTER GDEM tile"""
        download_url = tile_info['download_url']
        filename = tile_info['title']
        
        if not download_url:
            self.logger.warning(f"No download URL for tile: {filename}")
            return False
        
        # Create region-specific directory
        region_dir = self.download_dir / 'raw' / region
        region_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = region_dir / filename
        
        # Skip if file already exists
        if file_path.exists():
            self.logger.info(f"File already exists: {filename}")
            return True
        
        self.logger.info(f"Downloading: {filename}")
        
        try:
            response = self.session.get(download_url, stream=True)
            response.raise_for_status()
            
            total_size = int(response.headers.get('content-length', 0))
            downloaded = 0
            
            with open(file_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        
                        if total_size > 0:
                            progress = (downloaded / total_size) * 100
                            print(f"\rDownloading {filename}: {progress:.1f}%", end='', flush=True)
            
            print()  # New line after progress
            self.logger.info(f"Successfully downloaded: {filename}")
            return True
            
        except requests.RequestException as e:
            self.logger.error(f"Failed to download {filename}: {e}")
            if file_path.exists():
                file_path.unlink()  # Remove partial file
            return False
    
    def download_region(self, region: str, max_tiles: int = None) -> bool:
        """Download all available tiles for a region"""
        self.logger.info(f"Starting download for region: {region}")
        
        # Authenticate
        self.authenticate()
        
        # Get available tiles
        tiles = self.get_available_tiles(region)
        
        if not tiles:
            self.logger.warning(f"No tiles found for region: {region}")
            return False
        
        # Limit number of tiles if specified
        if max_tiles:
            tiles = tiles[:max_tiles]
            self.logger.info(f"Limited to {max_tiles} tiles")
        
        # Download tiles
        successful_downloads = 0
        failed_downloads = 0
        
        for i, tile in enumerate(tiles, 1):
            self.logger.info(f"Processing tile {i}/{len(tiles)}: {tile['title']}")
            
            if self.download_tile(tile, region):
                successful_downloads += 1
            else:
                failed_downloads += 1
            
            # Small delay to be respectful to the server
            time.sleep(1)
        
        self.logger.info(f"Download completed for {region}")
        self.logger.info(f"Successful: {successful_downloads}, Failed: {failed_downloads}")
        
        return successful_downloads > 0
    
    def list_available_regions(self):
        """List all available regions"""
        print("\nAvailable Regions:")
        print("=" * 50)
        
        region_names = {
            'USA': 'United States',
            'CAN': 'Canada', 
            'GBR': 'United Kingdom',
            'DEU': 'Germany',
            'FRA': 'France',
            'JPN': 'Japan',
            'AUS': 'Australia'
        }
        
        for code, name in region_names.items():
            bounds = self.region_bounds[code]
            print(f"{code:3} - {name}")
            print(f"     Bounds: {bounds['west']:.1f}°W to {bounds['east']:.1f}°E, "
                  f"{bounds['south']:.1f}°S to {bounds['north']:.1f}°N")
            print()
    
    def get_region_info(self, region: str) -> Dict:
        """Get information about a specific region"""
        if region not in self.region_bounds:
            raise ValueError(f"Unsupported region: {region}")
        
        bounds = self.region_bounds[region]
        region_dir = self.download_dir / 'raw' / region
        
        info = {
            'region': region,
            'bounds': bounds,
            'downloaded_files': [],
            'total_size': 0
        }
        
        if region_dir.exists():
            for file_path in region_dir.glob('*.tif'):
                file_size = file_path.stat().st_size
                info['downloaded_files'].append({
                    'filename': file_path.name,
                    'size': file_size,
                    'size_mb': file_size / (1024 * 1024)
                })
                info['total_size'] += file_size
        
        info['total_size_mb'] = info['total_size'] / (1024 * 1024)
        info['file_count'] = len(info['downloaded_files'])
        
        return info

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(description='ASTER GDEM Terrain Data Downloader')
    parser.add_argument('--region', '-r', help='Region code (e.g., USA, CAN, GBR)')
    parser.add_argument('--username', '-u', help='NASA Earthdata username')
    parser.add_argument('--password', '-p', help='NASA Earthdata password')
    parser.add_argument('--download-dir', '-d', help='Download directory')
    parser.add_argument('--max-tiles', '-m', type=int, help='Maximum number of tiles to download')
    parser.add_argument('--list-regions', action='store_true', help='List available regions')
    parser.add_argument('--info', help='Get information about a region')
    
    args = parser.parse_args()
    
    # Initialize downloader
    downloader = ASTERGDEMDownloader(
        username=args.username,
        password=args.password,
        download_dir=args.download_dir
    )
    
    if args.list_regions:
        downloader.list_available_regions()
        return
    
    if args.info:
        try:
            info = downloader.get_region_info(args.info)
            print(f"\nRegion Information: {args.info}")
            print("=" * 50)
            print(f"Bounds: {info['bounds']['west']:.1f}°W to {info['bounds']['east']:.1f}°E, "
                  f"{info['bounds']['south']:.1f}°S to {info['bounds']['north']:.1f}°N")
            print(f"Downloaded files: {info['file_count']}")
            print(f"Total size: {info['total_size_mb']:.1f} MB")
            
            if info['downloaded_files']:
                print("\nDownloaded files:")
                for file_info in info['downloaded_files']:
                    print(f"  {file_info['filename']} ({file_info['size_mb']:.1f} MB)")
        except ValueError as e:
            print(f"Error: {e}")
        return
    
    if not args.region:
        print("Error: Region is required. Use --list-regions to see available options.")
        return
    
    # Download data
    try:
        success = downloader.download_region(args.region, max_tiles=args.max_tiles)
        if success:
            print(f"\nDownload completed successfully for region: {args.region}")
        else:
            print(f"\nDownload failed for region: {args.region}")
            sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
