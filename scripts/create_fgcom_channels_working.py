#!/usr/bin/env python3
"""
FGcom-mumble Channel Creation Script
Based on murmur-rest implementation

This script creates the required fgcom-mumble channel on the Mumble server
using the Ice interface.
"""

import sys
import os
import Ice
import time

# Ice connection configuration
ICE_HOST = 'Meta:tcp -h 127.0.0.1 -p 6502'
ICE_SECRET = ''  # Empty for our setup

def create_fgcom_channel():
    """Create the fgcom-mumble channel on the Mumble server"""
    
    print("FGcom-mumble Channel Creation Script")
    print("=" * 40)
    
    try:
        # Initialize Ice
        print("Initializing Ice...")
        communicator = Ice.initialize()
        
        # Connect to Mumble server
        print(f"Connecting to Mumble server at {ICE_HOST}...")
        meta = communicator.stringToProxy(ICE_HOST)
        meta = meta.ice_uncheckedCast()
        
        # Get server list
        print("Getting server list...")
        servers = meta.getBootedServers()
        print(f"Found {len(servers)} running servers")
        
        if not servers:
            print("ERROR: No Mumble servers are running!")
            return False
        
        # Use the first server (usually server ID 1)
        server_id = servers[0]
        print(f"Using server ID: {server_id}")
        
        # Get server object
        server = meta.getServer(server_id)
        
        # Check if fgcom-mumble channel already exists
        print("Checking for existing fgcom-mumble channel...")
        try:
            # Try to get channel by name (this will fail if channel doesn't exist)
            channels = server.getChannels()
            fgcom_channel_exists = False
            
            for channel_id, channel in channels.items():
                if channel.name == "fgcom-mumble":
                    print(f"Channel 'fgcom-mumble' already exists with ID {channel_id}")
                    fgcom_channel_exists = True
                    break
            
            if not fgcom_channel_exists:
                print("Creating fgcom-mumble channel...")
                # Create the channel (parent=0 means root channel)
                new_channel_id = server.addChannel("fgcom-mumble", 0)
                print(f"Successfully created fgcom-mumble channel with ID {new_channel_id}")
            else:
                print("fgcom-mumble channel already exists, no action needed")
                
        except Exception as e:
            print(f"Error checking/creating channel: {e}")
            return False
        
        # Clean up
        communicator.destroy()
        print("Channel creation completed successfully!")
        return True
        
    except Exception as e:
        print(f"ERROR: Failed to create channel: {e}")
        print(f"Error type: {type(e).__name__}")
        return False

def main():
    """Main function"""
    print("Starting FGcom-mumble channel creation...")
    
    # Check if Mumble server is running
    print("Checking if Mumble server is running...")
    try:
        import subprocess
        result = subprocess.run(['systemctl', 'is-active', 'mumble-server'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print("ERROR: Mumble server is not running!")
            print("Please start the Mumble server first:")
            print("  sudo systemctl start mumble-server")
            return 1
        else:
            print("Mumble server is running")
    except Exception as e:
        print(f"Warning: Could not check Mumble server status: {e}")
    
    # Create the channel
    success = create_fgcom_channel()
    
    if success:
        print("\n✅ SUCCESS: fgcom-mumble channel created successfully!")
        print("You can now start the FGcom-mumble bots.")
        return 0
    else:
        print("\n❌ FAILED: Could not create fgcom-mumble channel")
        print("Please check the error messages above and try again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
